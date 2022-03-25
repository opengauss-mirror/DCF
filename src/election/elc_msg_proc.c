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
 * elc_msg_proc.c
 *    election process
 *
 * IDENTIFICATION
 *    src/election/elc_msg_proc.c
 *
 * -------------------------------------------------------------------------
 */

#include "elc_msg_proc.h"
#include "elc_stream.h"
#include "stg_manager.h"
#include "replication.h"
#include "cm_timer.h"
#include "util_defs.h"
#include "elc_status_check.h"

#ifdef __cplusplus
extern "C" {
#endif

#define WM_NORMAL_2_MINORITY_CANDIDATE_TERM_INC 1000

static status_t elc_set_candidate_term(uint32 stream_id, uint32 node_id, uint64 current_term);

status_t proc_node_voting(uint32 stream_id, uint32 src_node_id)
{
    uint32 voting_weight;
    bool32 is_voter = CM_FALSE;
    CM_RETURN_IFERR(md_is_voter(stream_id, src_node_id, &is_voter));
    if (is_voter) {
        CM_RETURN_IFERR(elc_get_voting_weight(stream_id, src_node_id, &voting_weight));
        CM_RETURN_IFERR(elc_stream_increase_vote_count(stream_id, voting_weight));
    }

    LOG_RUN_INF("[ELC]get vote from stream_id=%u, node_id=%u, term=%llu, vote_count=%u", stream_id, src_node_id,
        elc_stream_get_current_term(stream_id), elc_stream_get_vote_count(stream_id));
    return CM_SUCCESS;
}

status_t proc_node_voting_no(uint32 stream_id, uint32 src_node_id)
{
    uint32 voting_weight;
    bool32 is_voter = CM_FALSE;
    CM_RETURN_IFERR(md_is_voter(stream_id, src_node_id, &is_voter));
    if (is_voter) {
        CM_RETURN_IFERR(elc_get_voting_weight(stream_id, src_node_id, &voting_weight));
        CM_RETURN_IFERR(elc_stream_increase_vote_no_count(stream_id, voting_weight));
    }
    LOG_RUN_INF("[ELC]get vote no from stream_id=%u, node_id=%u, term=%llu, vote_no_count=%u", stream_id, src_node_id,
        elc_stream_get_current_term(stream_id), elc_stream_get_vote_no_count(stream_id));
    return CM_SUCCESS;
}

bool32 is_win(uint32 stream_id)
{
    bool32 is_win;

    if (elc_stream_is_win(stream_id, &is_win) != CM_SUCCESS) {
        return CM_FALSE;
    }

    return is_win;
}

bool32 is_not_win(uint32 stream_id)
{
    bool32 is_not_win = CM_FALSE;
    if (elc_stream_is_not_win(stream_id, &is_not_win) != CM_SUCCESS) {
        return CM_FALSE;
    }
    return is_not_win;
}

status_t elc_vote_req(uint32 stream_id, uint32 vote_flag)
{
    dcf_work_mode_t work_mode = elc_stream_get_work_mode(stream_id);
    uint32 node_id = elc_stream_get_current_node();
    uint64 current_term = elc_stream_get_current_term(stream_id);

    CM_RETURN_IFERR(elc_stream_set_votefor(stream_id, node_id));
    LOG_DEBUG_INF("[ELC]Set votefor as self when elc vote req, stream_id=%u, votefor=%u", stream_id, node_id);

    elc_stream_reset_vote_count(stream_id);
    CM_RETURN_IFERR(proc_node_voting(stream_id, node_id));

    if (is_win(stream_id))  {
        CM_RETURN_IFERR(elc_set_candidate_term(stream_id, node_id, current_term));
        LOG_RUN_INF("[ELC]set self as leader after voting for self, stream_id=%u, work_mode=%d", stream_id, work_mode);
        CM_RETURN_IFERR(elc_stream_set_role(stream_id, DCF_ROLE_LEADER));
        return CM_SUCCESS;
    }

    mec_message_t pack;
    elc_vote_t req_vote;
    req_vote.candidate_id = node_id;
    req_vote.candidate_term = current_term;
    req_vote.last_log = stg_last_log_id(stream_id);
    req_vote.vote_flag = vote_flag;
    req_vote.work_mode = elc_stream_get_work_mode(stream_id);

    CM_RETURN_IFERR(mec_alloc_pack(&pack, MEC_CMD_VOTE_REQUEST_RPC_REQ, node_id, CM_INVALID_NODE_ID, stream_id));
    if (elc_encode_vote_req(&pack, &req_vote) != CM_SUCCESS) {
        mec_release_pack(&pack);
        LOG_DEBUG_ERR("[ELC]Encode vote request failed");
        return CM_ERROR;
    }

    uint64 inst_bits[INSTS_BIT_SZ] = {0};
    uint64 success_inst[INSTS_BIT_SZ];
    if (elc_stream_vote_node_list(stream_id, inst_bits) != CM_SUCCESS) {
        mec_release_pack(&pack);
        LOG_DEBUG_ERR("[ELC]Prepare vote node list failed");
        return CM_ERROR;
    }
    mec_broadcast(stream_id, inst_bits, &pack, success_inst);
    LOG_RUN_INF("[ELC]elc vote req broadcast, stream_id=%u candidate_id=%u candidate_term=%llu last_log.term=%llu "
        "last_log.index=%llu vote_flag=0x%x work_mode=%d", stream_id, req_vote.candidate_id, req_vote.candidate_term,
        req_vote.last_log.term, req_vote.last_log.index, req_vote.vote_flag, req_vote.work_mode);
    mec_release_pack(&pack);
    return CM_SUCCESS;
}

bool32 elc_check_last_log(log_id_t* log_a, log_id_t* log_b)
{
    if (log_id_cmp(log_a, log_b) >= 0) {
        return CM_TRUE;
    }
    return CM_FALSE;
}

static status_t elc_judge_vote_postproc(uint32 stream_id, uint32 src_node, const elc_vote_t* req_vote,
    bool32 vote_granted)
{
    dcf_role_t role = elc_stream_get_role(stream_id);
    uint64 current_term = elc_stream_get_current_term(stream_id);
    uint64 candidate_term = req_vote->candidate_term;

    if (vote_granted == CM_TRUE) {
        if (role != DCF_ROLE_LOGGER && role != DCF_ROLE_PASSIVE) {
            CM_RETURN_IFERR(elc_stream_set_role(stream_id, DCF_ROLE_FOLLOWER));
        }
        CM_RETURN_IFERR(elc_stream_set_votefor(stream_id, src_node));
        LOG_DEBUG_INF("[ELC]Set votefor when judge vote postproc, stream_id=%u, votefor=%u", stream_id, src_node);
        CM_RETURN_IFERR(elc_stream_set_term(stream_id, candidate_term));
        CM_RETURN_IFERR(elc_stream_set_timeout(stream_id, cm_clock_now()));
    } else if (current_term < candidate_term) {
        CM_RETURN_IFERR(elc_stream_set_term(stream_id, candidate_term));
        if (role != DCF_ROLE_LOGGER && role != DCF_ROLE_PASSIVE) {
            CM_RETURN_IFERR(elc_stream_set_role(stream_id, DCF_ROLE_FOLLOWER));
        }
        CM_RETURN_IFERR(elc_stream_set_votefor(stream_id, CM_INVALID_NODE_ID));
        LOG_DEBUG_INF("[ELC]Set votefor as invalid nodeid when judge vote postproc,"
            " current_term=%llu, candidate_term=%llu", current_term, candidate_term);
    }
    return CM_SUCCESS;
}

bool32 elc_need_demote_follow(uint32 stream_id, timespec_t now, uint32 elc_timeout_cnt)
{
    uint32 weight;
    uint32 elc_timeout = elc_stream_get_elc_timeout_ms();
    uint32 hb_ack_timeout_num = 0;
    uint32 voter_num = 0;
    dcf_node_role_t node_list[CM_MAX_NODE_COUNT];
    uint32 node_count;
    uint32 local_node_id = md_get_cur_node(stream_id);
    dcf_role_t default_role;
    if (elc_stream_get_work_mode(stream_id) != WM_NORMAL) {
        return CM_FALSE;
    }
    if (md_get_stream_node_roles(stream_id, node_list, &node_count) != CM_SUCCESS ||
        md_get_voter_num(stream_id, &voter_num) != CM_SUCCESS) {
        return CM_FALSE;
    }
    for (uint32 i = 0; i < node_count; i++) {
        uint32 node_id = node_list[i].node_id;
        default_role  = node_list[i].default_role;
        if (node_id == local_node_id || default_role == DCF_ROLE_PASSIVE) {
            continue;
        }
        uint64 hb_ack_time = elc_stream_get_hb_ack_time(stream_id, node_id);
        uint64 interval = (now < hb_ack_time) ? 0 : (uint64)(now - hb_ack_time);
        if (interval / MICROSECS_PER_MILLISEC > elc_timeout * elc_timeout_cnt) {
            LOG_DEBUG_WAR("[ELC]recv heartbeat ack timout from node_id=%u\n", node_id);
            CM_RETURN_IFERR(elc_get_voting_weight(stream_id, node_id, &weight));
            hb_ack_timeout_num += weight;
        }
        if (hb_ack_timeout_num >= ((voter_num + 1) / CM_2X_FIXED)) {
            LOG_DEBUG_INF("[ELC]Leader need demote follow, local_node_id:%u hb_ack_timeout_num:%u voter_num:%u",
                local_node_id, hb_ack_timeout_num, voter_num);
            return CM_TRUE;
        }
    }
    return CM_FALSE;
}

static bool32 elc_need_judge_vote(uint32 stream_id, uint32 src_node, const elc_vote_t* req_vote)
{
    uint64 current_term = elc_stream_get_current_term(stream_id);
    uint32 votefor = elc_stream_get_votefor(stream_id);
    timespec_t now = cm_clock_now();

    if (ELC_FORCE_VOTE(req_vote->vote_flag)) {
        return CM_TRUE;
    }

    if (votefor == CM_INVALID_NODE_ID || votefor == src_node) {
        return CM_TRUE;
    }

    if (current_term == req_vote->candidate_term && elc_stream_get_role(stream_id) == DCF_ROLE_LEADER &&
        !elc_need_demote_follow(stream_id, now, CM_1X_FIXED)) {
        LOG_RUN_INF("[ELC] leader no need to judge vote from src_node:%u, current_term=%llu", src_node, current_term);
        return CM_FALSE;
    }

    uint64 candidate_term = req_vote->candidate_term;
    if (ELC_PRE_VOTE(req_vote->vote_flag)) {
        candidate_term = candidate_term + 1;
    }

    if ((current_term == candidate_term || current_term == req_vote->candidate_term) &&
        elc_stream_get_role(stream_id) != DCF_ROLE_PRE_CANDIDATE) {
        timespec_t last_hb_time = elc_stream_get_timeout(stream_id);
        uint64 interval_time = ((uint64)(cm_clock_now() - last_hb_time)) / MICROSECS_PER_MILLISEC;
        if (interval_time <  elc_stream_get_elc_timeout_ms()) {
            LOG_RUN_INF("[ELC]not timeout yet, votefor=%u current_term=%llu candidate_term=%llu req_vote_flag=%u",
                elc_stream_get_votefor(stream_id), current_term, candidate_term, req_vote->vote_flag);
            return CM_FALSE;
        }
    }

    return CM_TRUE;
}

status_t elc_judge_vote(uint32 stream_id, uint32 src_node, elc_vote_t* req_vote, bool32* vote_granted)
{
    dcf_role_t role = elc_stream_get_role(stream_id);
    uint64 current_term = elc_stream_get_current_term(stream_id);
    dcf_work_mode_t work_mode = elc_stream_get_work_mode(stream_id);
    if (work_mode != req_vote->work_mode || role == DCF_ROLE_PASSIVE) {
        LOG_DEBUG_INF("[ELC]Not granted to node:%u, since judge as invalid vote, candidate_id=%u work_mode=%d, "
            "local node work_mode=%d role=%d", src_node, req_vote->candidate_id, req_vote->work_mode, work_mode, role);
        return CM_SUCCESS;
    }

    dcf_node_t node_info;
    CM_RETURN_IFERR(md_get_stream_node_ext(stream_id, src_node, &node_info));
    if (node_info.default_role == DCF_ROLE_PASSIVE) {
        LOG_DEBUG_INF("[ELC]Not granted to node:%u, since vote from passive role", src_node);
        return CM_SUCCESS;
    }

    uint64 candidate_term = req_vote->candidate_term;
    if (ELC_PRE_VOTE(req_vote->vote_flag)) {
        candidate_term = candidate_term + 1;
    }

    if (!elc_need_judge_vote(stream_id, src_node, req_vote)) {
        return CM_SUCCESS;
    }

    if (current_term > candidate_term) {
        *vote_granted = CM_FALSE;
        LOG_DEBUG_INF("[ELC]Not granted to node:%u, current_term(%llu) > candidate_term(%llu)", src_node, current_term,
            candidate_term);
        return CM_SUCCESS;
    }

    log_id_t last_log = stg_last_log_id(stream_id);
    if (elc_check_last_log(&req_vote->last_log, &last_log)) {
        *vote_granted = CM_TRUE;
    }
    LOG_DEBUG_INF("[ELC]node:%u,req_last_log term=%llu index=%llu, local_last_log.term=%llu,index=%llu,granted=%u",
        src_node, req_vote->last_log.term, req_vote->last_log.index, last_log.term, last_log.index, *vote_granted);

    if (ELC_PRE_VOTE(req_vote->vote_flag)) {
        LOG_DEBUG_INF("[ELC]elc judge vote return since it's pre vote(vote_flag=0x%x)", req_vote->vote_flag);
        return CM_SUCCESS;
    }

    CM_RETURN_IFERR(elc_judge_vote_postproc(stream_id, src_node, req_vote, *vote_granted));

    return CM_SUCCESS;
}

status_t elc_promote_req(uint32 stream_id, uint32 node_id)
{
    uint32 src_node_id = elc_stream_get_current_node();
    mec_message_t pack;
    elc_hb_t req_vote;
    req_vote.term = elc_stream_get_current_term(stream_id);
    req_vote.send_time = cm_clock_now();
    CM_RETURN_IFERR(mec_alloc_pack(&pack, MEC_CMD_PROMOTE_LEADER_RPC_REQ, src_node_id, node_id, stream_id));
    if (elc_encode_hb_req(&pack, &req_vote) != CM_SUCCESS) {
        mec_release_pack(&pack);
        LOG_DEBUG_ERR("[ELC]encode failed, when send promote message");
        return CM_ERROR;
    }
    status_t status = mec_send_data(&pack);
    mec_release_pack(&pack);
    return status;
}

status_t elc_promote_proc(mec_message_t *pack)
{
    uint32 stream_id = pack->head->stream_id;
    uint32 src_node_id = pack->head->src_inst;
    LOG_DEBUG_INF("[ELC]Receive promote message from stream_id=%u, node_id=%u", stream_id, src_node_id);

    elc_hb_t ack_vote;
    CM_RETURN_IFERR(elc_decode_hb_req(pack, &ack_vote));

    elc_stream_lock_x(stream_id);
    uint64 current_term = elc_stream_get_current_term(stream_id);
    if (ack_vote.term < current_term) {
        LOG_DEBUG_INF("[ELC]term has changed, ignore this message, stream_id=%u, src_node_id=%u",
            stream_id, src_node_id);
        elc_stream_unlock(stream_id);
        return CM_SUCCESS;
    }
    dcf_role_t role = elc_stream_get_role(stream_id);
    if (role == DCF_ROLE_PASSIVE || role == DCF_ROLE_LOGGER) {
        LOG_DEBUG_INF("[ELC]role(%d) can't be elected, ignore this message, stream_id=%u, src_node_id=%u",
            role, stream_id, src_node_id);
        elc_stream_unlock(stream_id);
        return CM_SUCCESS;
    }
    CM_RETURN_IFERR_EX(elc_stream_set_timeout(stream_id, cm_clock_now()), elc_stream_unlock(stream_id));
    CM_RETURN_IFERR_EX(elc_stream_set_role(stream_id, DCF_ROLE_CANDIDATE), elc_stream_unlock(stream_id));
    CM_RETURN_IFERR_EX(elc_stream_set_term(stream_id, current_term + 1), elc_stream_unlock(stream_id));
    uint32 vote_flag = VOTE_FLAG_FORCE_VOTE;
    status_t ret = elc_vote_req(stream_id, vote_flag);
    elc_stream_unlock(stream_id);
    return ret;
}

status_t elc_vote_proc(mec_message_t *pack)
{
    elc_vote_t req_vote;
    uint32 stream_id = pack->head->stream_id;
    uint32 node_id = elc_stream_get_current_node();

    LOG_DEBUG_INF("[ELC]Receive voting request from node_id=%u, stream_id=%u, current_node=%u",
        pack->head->src_inst, stream_id, node_id);

    CM_RETURN_IFERR(elc_decode_vote_req(pack, &req_vote));

    elc_stream_lock_x(stream_id);

    bool32 vote_granted = CM_FALSE;
    CM_RETURN_IFERR_EX(elc_judge_vote(stream_id, pack->head->src_inst, &req_vote, &vote_granted),
        elc_stream_unlock(stream_id));

    mec_message_t ack_pack;
    CM_RETURN_IFERR_EX(mec_alloc_pack(&ack_pack, MEC_CMD_VOTE_REQUEST_RPC_ACK, node_id,
        pack->head->src_inst, stream_id), elc_stream_unlock(stream_id));
    elc_vote_ack_t ack_vote;
    ack_vote.term = elc_stream_get_current_term(stream_id);
    ack_vote.vote_granted = vote_granted;
    ack_vote.work_mode = elc_stream_get_work_mode(stream_id);
    ack_vote.vote_flag = req_vote.vote_flag;

    elc_stream_unlock(stream_id);

    if (elc_encode_vote_ack(&ack_pack, &ack_vote) != CM_SUCCESS) {
        mec_release_pack(&ack_pack);
        return CM_ERROR;
    }

    LOG_RUN_INF("[ELC]Send response to node_id=%u, stream_id=%u, current_node=%u, current_term=%llu, vote_granted=%u, "
        "work_mode=%d", pack->head->src_inst, stream_id, node_id, ack_vote.term, vote_granted, ack_vote.work_mode);

    status_t status = mec_send_data(&ack_pack);
    mec_release_pack(&ack_pack);
    return status;
}

static status_t elc_set_candidate_term(uint32 stream_id, uint32 node_id, uint64 current_term)
{
    dcf_work_mode_t work_mode = elc_stream_get_work_mode(stream_id);
    if (work_mode == WM_NORMAL) {
        return elc_stream_set_term(stream_id, current_term + 1);
    } else if (work_mode == WM_MINORITY) {
        dcf_work_mode_t prev_work_mode = elc_stream_get_vote_node_work_mode(stream_id, node_id);
        if (prev_work_mode == WM_NORMAL) {
            CM_RETURN_IFERR(elc_stream_set_vote_node_work_mode(stream_id, node_id, WM_MINORITY));
            return elc_stream_set_term(stream_id, current_term + WM_NORMAL_2_MINORITY_CANDIDATE_TERM_INC);
        } else {
            return elc_stream_set_term(stream_id, current_term + 1);
        }
    }
    return CM_SUCCESS;
}

status_t vote_grant_proc(uint32 stream_id, uint32 node_id, uint32 src_node, dcf_role_t role, uint64 current_term,
    const elc_vote_ack_t *ack_vote)
{
    if (role == DCF_ROLE_PRE_CANDIDATE) {
        if (ack_vote->work_mode != elc_stream_get_work_mode(stream_id)) {
            return CM_SUCCESS;
        }
        if (ack_vote->term > current_term) {
            return CM_SUCCESS;
        }
        CM_RETURN_IFERR(proc_node_voting(stream_id, src_node));
        if (!is_win(stream_id)) {
            return CM_SUCCESS;
        }
        LOG_RUN_INF("[ELC]pre-voting succeeded, stream_id=%u, node_id=%u, current_term=%llu",
            stream_id, node_id, current_term);
        CM_RETURN_IFERR(elc_stream_set_timeout(stream_id, cm_clock_now()));
        CM_RETURN_IFERR(elc_stream_set_role(stream_id, DCF_ROLE_CANDIDATE));
        CM_RETURN_IFERR(elc_set_candidate_term(stream_id, node_id, current_term));
        uint32 vote_flag = VOTE_FLAG_INIT;
        CM_RETURN_IFERR(elc_vote_req(stream_id, vote_flag));
    } else if (role == DCF_ROLE_CANDIDATE) {
        if (ack_vote->work_mode != elc_stream_get_work_mode(stream_id)) {
            return CM_SUCCESS;
        }
        if (ack_vote->term != current_term) {
            LOG_RUN_WAR("[ELC]term inconsistency, ignore this message, stream_id=%u, node_id=%u,"
                "current_term=%llu, peer_node=%u, peer_term=%llu",
                stream_id, node_id, current_term, src_node, ack_vote->term);
            return CM_SUCCESS;
        }
        CM_RETURN_IFERR(proc_node_voting(stream_id, src_node));
        if (!is_win(stream_id)) {
            return CM_SUCCESS;
        }
        LOG_RUN_INF("[ELC]election is successful, stream_id=%u, node_id=%u, current_term=%llu",
            stream_id, node_id, current_term);
        if (ELC_FORCE_VOTE(ack_vote->vote_flag)) {
            LOG_RUN_INF("[ELC]set force_vote_flag, stream_id=%u, src_node=%u", stream_id, src_node);
            elc_stream_set_force_vote_flag(stream_id, CM_TRUE);
        }
        CM_RETURN_IFERR(elc_stream_set_role(stream_id, DCF_ROLE_LEADER));
        timespec_t now = cm_clock_now();
        for (uint32 j = 0; j < CM_MAX_NODE_COUNT; j++) {
            CM_RETURN_IFERR(elc_stream_set_hb_ack_time(stream_id, j, now));
        }
        CM_RETURN_IFERR(elc_stream_set_old_leader(stream_id, node_id));
        CM_RETURN_IFERR(elc_send_status_info(stream_id));
    }
    return CM_SUCCESS;
}

status_t elc_vote_ack_proc_inside(uint32 stream_id, uint32 src_node, elc_vote_ack_t* ack_vote)
{
    uint32 node_id = elc_stream_get_current_node();
    dcf_role_t role = elc_stream_get_role(stream_id);
    uint64 current_term = elc_stream_get_current_term(stream_id);
    int32 work_mode = elc_stream_get_work_mode(stream_id);

    LOG_RUN_INF("[ELC]receive ack from node_id=%u, stream_id=%u, current_node=%u, current_term=%llu, role=%d, "
        "work_mode=%d peer_term=%llu, vote_granted=%u work_mode=%d", src_node, stream_id, node_id, current_term, role,
        work_mode, ack_vote->term, ack_vote->vote_granted, ack_vote->work_mode);

    if (role != DCF_ROLE_PRE_CANDIDATE && role != DCF_ROLE_CANDIDATE) {
        LOG_DEBUG_INF("[ELC]role changed already, ignore ack");
        return CM_SUCCESS;
    }

    if (ack_vote->vote_granted) {
        CM_RETURN_IFERR(vote_grant_proc(stream_id, node_id, src_node, role, current_term, ack_vote));
    } else { // no vote been obtained
        LOG_RUN_INF("[ELC]no vote been obtained, stream_id=%u, node_id=%u, current_term=%llu, "
            "peer_node=%u, peer_term=%llu",
            stream_id, node_id, current_term, src_node, ack_vote->term);

        if (work_mode != ack_vote->work_mode) {
            return CM_SUCCESS;
        }

        if (ack_vote->term > current_term) {
            CM_RETURN_IFERR(elc_stream_set_term(stream_id, ack_vote->term));
            if (role != DCF_ROLE_LOGGER && role != DCF_ROLE_PASSIVE) {
                CM_RETURN_IFERR(elc_stream_set_role(stream_id, DCF_ROLE_FOLLOWER));
            }
            CM_RETURN_IFERR(elc_stream_set_votefor(stream_id, CM_INVALID_NODE_ID));
            LOG_DEBUG_INF("[ELC]Set votefor as invalid nodeid when vote_ack_proc,"
                " current_term=%llu, ack_vote term=%llu", current_term, ack_vote->term);
        }

        CM_RETURN_IFERR(proc_node_voting_no(stream_id, src_node));
        if (is_not_win(stream_id)) {
            timespec_t date = cm_clock_now() - elc_stream_get_elc_timeout_ms() * MICROSECS_PER_MILLISEC;
            (void)elc_stream_set_timeout(stream_id, date);
            LOG_DEBUG_INF("[ELC]Election is defeated, set last hb time:%lld", date);
        }
    }

    return CM_SUCCESS;
}
status_t elc_vote_ack_proc(mec_message_t *pack)
{
    LOG_DEBUG_INF("[ELC]begin elc_vote_ack_proc");
    uint32 stream_id = pack->head->stream_id;
    elc_vote_ack_t ack_vote;
    CM_RETURN_IFERR(elc_decode_vote_ack(pack, &ack_vote));

    elc_stream_lock_x(stream_id);
    status_t ret = elc_vote_ack_proc_inside(stream_id, pack->head->src_inst, &ack_vote);
    elc_stream_unlock(stream_id);
    LOG_DEBUG_INF("[ELC]end elc_vote_ack_proc");
    return ret;
}

static status_t elc_hb_proc(mec_message_t *pack, elc_hb_t *hb_req, const rcv_node_info_t *rcv_info)
{
    uint32 stream_id = pack->head->stream_id;
    uint32 src_node_id = pack->head->src_inst;
    LOG_DEBUG_INF("[ELC]Receive heartbeat from stream_id=%u, node_id=%u", stream_id, src_node_id);
    stat_record(HB_RECV_COUNT, 1);

    elc_stream_lock_x(stream_id);
    elc_stream_set_leader_group(stream_id, rcv_info->group);
    if (elc_stream_get_leader_start_time(stream_id) == 0) {
        elc_stream_set_leader_start_time(stream_id, cm_clock_now());
    }
    dcf_work_mode_t work_mode = elc_stream_get_work_mode(stream_id);
    if (work_mode == WM_MINORITY && hb_req->work_mode == WM_NORMAL) {
        LOG_DEBUG_INF("[ELC]Ignore heartbeat from node:%u as mismatched work mode, stream_id=%u",
            src_node_id, stream_id);
        elc_stream_unlock(stream_id);
        return CM_SUCCESS;
    }
    status_t ret = elc_stream_refresh_hb_time(stream_id, hb_req->term, hb_req->work_mode, src_node_id);
    elc_stream_unlock(stream_id);
    return ret;
}

static status_t elc_check_md_match_proc(uint32 stream_id, uint32 hb_ack_chksum, timespec_t now, bool32 *need_md_rep)
{
    timespec_t last_md_rep_time = elc_stream_get_last_md_rep_time(stream_id);
    uint32 chksum = md_get_checksum();

    LOG_DEBUG_INF("[ELC]Check metadata match proc, local chksum=%u recved hb_ack_chksum:%u", chksum, hb_ack_chksum);

    if (chksum == hb_ack_chksum) {
        return CM_SUCCESS;
    }

    uint64 interval_time = ((uint64)(now - last_md_rep_time)) / MICROSECS_PER_MILLISEC;
    if (interval_time >= CM_MD_MISMATCH_REP_INTERVAL && elc_stream_get_role(stream_id) == DCF_ROLE_LEADER) {
        LOG_DEBUG_INF("[ELC]Check metadata as mismatched, leader need to rep metadata");
        *need_md_rep = CM_TRUE;
    }

    return CM_SUCCESS;
}

status_t elc_encode_status_info(mec_message_t* pack, uint32 stream_id, int64 send_time)
{
    rcv_node_info_t req_status;
    req_status.role = elc_stream_get_role(stream_id);
    req_status.group = elc_stream_get_my_group(stream_id);
    req_status.priority = elc_stream_get_priority(stream_id);
    req_status.is_in_majority = elc_is_in_majority(stream_id);
    req_status.is_future_hb = elc_stream_is_future_hb(stream_id);
    CM_RETURN_IFERR(elc_encode_status_check_req(pack, &req_status));

    elc_hb_t req_hb;
    req_hb.term = elc_stream_get_current_term(stream_id);
    req_hb.work_mode = elc_stream_get_work_mode(stream_id);
    req_hb.md_chksum = md_get_checksum();
    req_hb.send_time = send_time;
    CM_RETURN_IFERR(elc_encode_hb_req(pack, &req_hb));
    return CM_SUCCESS;
}

status_t elc_send_status_info(uint32 stream_id)
{
    uint32 cur_node_id = md_get_cur_node();
    mec_message_t pack;
    CM_RETURN_IFERR(mec_alloc_pack(&pack, MEC_CMD_STATUS_CHECK_RPC_REQ, cur_node_id, CM_INVALID_NODE_ID, stream_id));

    if (elc_encode_status_info(&pack, stream_id, cm_clock_now()) != CM_SUCCESS) {
        mec_release_pack(&pack);
        LOG_DEBUG_ERR("[ELC]send_status_info encode failed, stream_id=%u,node_id=%u", stream_id, cur_node_id);
        return CM_ERROR;
    }

    uint64 inst_bits[INSTS_BIT_SZ] = {0};
    uint64 success_inst[INSTS_BIT_SZ];
    if (elc_stream_vote_node_list(stream_id, inst_bits) != CM_SUCCESS) {
        mec_release_pack(&pack);
        LOG_DEBUG_ERR("[ELC]status_check prepare node list failed, stream_id=%u,node_id=%u", stream_id, cur_node_id);
        return CM_ERROR;
    }
    mec_broadcast(stream_id, inst_bits, &pack, success_inst);
    if (elc_stream_get_role(stream_id) == DCF_ROLE_LEADER) {
        stat_record(HB_SEND_COUNT, 1);
    }
    LOG_DEBUG_INF("[ELC]elc status info send end, stream_id=%u,node_id=%u", stream_id, cur_node_id);
    mec_release_pack(&pack);
    return CM_SUCCESS;
}

static status_t elc_status_info_ack(uint32 stream_id, uint32 dst_node, int64 req_hb_send_time)
{
    mec_message_t pack;
    uint32 src_node = elc_stream_get_current_node();
    CM_RETURN_IFERR(mec_alloc_pack(&pack, MEC_CMD_STATUS_CHECK_RPC_ACK, src_node, dst_node, stream_id));

    elc_stream_lock_s(stream_id);
    status_t ret = elc_encode_status_info(&pack, stream_id, req_hb_send_time);
    elc_stream_unlock(stream_id);
    if (ret != CM_SUCCESS) {
        mec_release_pack(&pack);
        LOG_DEBUG_ERR("[ELC]status_info_ack encode failed, stream_id=%u,node_id=%u", stream_id, src_node);
        return CM_ERROR;
    }

    ret = mec_send_data(&pack);
    LOG_DEBUG_INF("[ELC]status_info_ack end, stream_id=%u,node_id=%u", stream_id, src_node);
    mec_release_pack(&pack);
    return ret;
}

status_t elc_status_check_req_proc(mec_message_t *pack)
{
    uint32 stream_id = pack->head->stream_id;
    uint32 src_node = pack->head->src_inst;
    LOG_DEBUG_INF("[ELC]recv status_check_req: stream_id=%u, src_node=%u", stream_id, src_node);

    rcv_node_info_t rcv_info;
    CM_RETURN_IFERR(elc_decode_status_check_req(pack, &rcv_info));
    rcv_info.last_recv_time = cm_clock_now();
    elc_save_status_check_info(stream_id, src_node, &rcv_info);

    if (rcv_info.role == DCF_ROLE_LEADER) {
        elc_hb_t hb_req;
        CM_RETURN_IFERR(elc_decode_hb_req(pack, &hb_req));
        CM_RETURN_IFERR(elc_hb_proc(pack, &hb_req, &rcv_info));

        LOG_DEBUG_INF("[ELC]send status_info ack, stream_id=%u", stream_id);
        CM_RETURN_IFERR(elc_status_info_ack(stream_id, src_node, hb_req.send_time));
    }

    LOG_DEBUG_INF("[ELC]recv status_check_req end: stream_id=%u, src_node=%u", stream_id, src_node);
    return CM_SUCCESS;
}

status_t elc_status_check_ack_proc(mec_message_t *pack)
{
    uint32 stream_id = pack->head->stream_id;
    uint32 src_node_id = pack->head->src_inst;

    rcv_node_info_t rcv_info;
    CM_RETURN_IFERR(elc_decode_status_check_req(pack, &rcv_info));

    elc_hb_t ack_hb;
    CM_RETURN_IFERR(elc_decode_hb_req(pack, &ack_hb));
    stat_record(HB_RTT, (uint64)(cm_clock_now() - ack_hb.send_time));
    LOG_DEBUG_INF("[ELC]Receive heartbeat ack from stream_id=%u, node_id=%u, ack_hb's term:%llu work_mode:%u "
        "md_chksum:%u", stream_id, src_node_id, ack_hb.term, ack_hb.work_mode, ack_hb.md_chksum);

    elc_stream_lock_x(stream_id);
    status_t ret = elc_stream_set_vote_node_work_mode(stream_id, src_node_id, ack_hb.work_mode);
    if (ret != CM_SUCCESS) {
        elc_stream_unlock(stream_id);
        return ret;
    }

    bool32 need_md_rep = CM_FALSE;
    timespec_t now = cm_clock_now();
    ret = elc_stream_refresh_hb_ack_time(stream_id, ack_hb.term, src_node_id);
    if (ret != CM_SUCCESS) {
        elc_stream_unlock(stream_id);
        return ret;
    }
    ret = elc_check_md_match_proc(stream_id, ack_hb.md_chksum, now, &need_md_rep);
    elc_stream_unlock(stream_id);
    if (need_md_rep == CM_TRUE) {
        uint32 size;
        CM_RETURN_IFERR(md_set_status(META_CATCH_UP));
        if (md_to_string(md_get_buffer(), CM_METADATA_DEF_MAX_LEN, &size) != CM_SUCCESS) {
            CM_RETURN_IFERR(md_set_status(META_NORMAL));
            return CM_ERROR;
        }
        LOG_DEBUG_INF("[ELC]Check metadata as mismatched, leader prepare to rep metadata:%s", md_get_buffer());
        if (rep_write(stream_id, md_get_buffer(), size, CFG_LOG_KEY(src_node_id, OP_FLAG_ALL),
            ENTRY_TYPE_CONF, NULL) != CM_SUCCESS) {
            CM_RETURN_IFERR(md_set_status(META_NORMAL));
            return CM_ERROR;
        }
        CM_RETURN_IFERR(md_set_status(META_NORMAL));
        CM_RETURN_IFERR(elc_stream_set_last_md_rep_time(stream_id, now));
    }
    return ret;
}

#ifdef __cplusplus
}
#endif
