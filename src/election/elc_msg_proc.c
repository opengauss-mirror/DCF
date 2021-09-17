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

#ifdef __cplusplus
extern "C" {
#endif

#define WM_NORMAL_2_MINORITY_CANDIDATE_TERM_INC 1000

static status_t elc_set_candidate_term(uint32 stream_id, uint32 node_id, uint64 current_term);

static status_t elc_hb_ack(uint32 stream_id, uint32 dst_node, mec_command_t cmd, int64 req_hb_send_time);

status_t proc_node_voting(uint32 stream_id, uint32 src_node_id)
{
    bool32 is_voter = CM_FALSE;
    CM_RETURN_IFERR(md_is_voter(stream_id, src_node_id, &is_voter));
    if (is_voter) {
        CM_RETURN_IFERR(elc_stream_increase_vote_count(stream_id));
    }

    LOG_RUN_INF("[ELC]get vote from stream_id=%u, node_id=%u, term=%llu, vote_count=%u", stream_id, src_node_id,
        elc_stream_get_current_term(stream_id), elc_stream_get_vote_count(stream_id));
    return CM_SUCCESS;
}

status_t proc_node_voting_no(uint32 stream_id, uint32 src_node_id)
{
    bool32 is_voter = CM_FALSE;
    CM_RETURN_IFERR(md_is_voter(stream_id, src_node_id, &is_voter));
    if (is_voter) {
        CM_RETURN_IFERR(elc_stream_increase_vote_no_count(stream_id));
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
    uint32 node_id = elc_stream_get_current_node();
    uint64 current_term = elc_stream_get_current_term(stream_id);

    CM_RETURN_IFERR(elc_stream_set_votefor(stream_id, node_id));
    LOG_DEBUG_INF("[ELC]Set votefor as self when elc vote req, stream_id=%u, votefor=%u", stream_id, node_id);

    elc_stream_reset_vote_count(stream_id);
    CM_RETURN_IFERR(proc_node_voting(stream_id, node_id));

    if (elc_stream_get_work_mode(stream_id) == WM_MINORITY && is_win(stream_id))  {
        LOG_RUN_INF("[ELC]minority win and set self as leader after proc voting for self, stream_id=%u", stream_id);
        CM_RETURN_IFERR(elc_set_candidate_term(stream_id, node_id, current_term));
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

static status_t elc_judge_vote_postproc(uint32 stream_id, uint32 src_node, elc_vote_t* req_vote, bool32 vote_granted)
{
    dcf_role_t role = elc_stream_get_role(stream_id);
    uint64 current_term = elc_stream_get_current_term(stream_id);
    uint64 candidate_term = req_vote->candidate_term;
    if (ELC_PRE_VOTE(req_vote->vote_flag)) {
        candidate_term = candidate_term + 1;
    }

    if (vote_granted == CM_TRUE) {
        if (role != DCF_ROLE_LOGGER && role != DCF_ROLE_PASSIVE) {
            CM_RETURN_IFERR(elc_stream_set_role(stream_id, DCF_ROLE_FOLLOWER));
        }
        CM_RETURN_IFERR(elc_stream_set_votefor(stream_id, src_node));
        LOG_DEBUG_INF("[ELC]Set votefor when judge vote postproc, stream_id=%u, votefor=%u", stream_id, src_node);
        CM_RETURN_IFERR(elc_stream_set_term(stream_id, candidate_term));
        CM_RETURN_IFERR(elc_stream_set_timeout(stream_id, g_timer()->now));
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

    uint32 votefor = elc_stream_get_votefor(stream_id);
    if (!ELC_FORCE_VOTE(req_vote->vote_flag) && votefor != src_node && votefor != CM_INVALID_NODE_ID &&
        current_term == candidate_term && elc_stream_get_role(stream_id) != DCF_ROLE_PRE_CANDIDATE) {
        date_t last_hb_time = elc_stream_get_timeout(stream_id);
        uint64 interval_time = ((uint64)(g_timer()->now - last_hb_time)) / MICROSECS_PER_MILLISEC;
        if (interval_time <  elc_stream_get_elc_timeout_ms()) {
            LOG_DEBUG_INF("[ELC]not timeout yet, votefor=%u", elc_stream_get_votefor(stream_id));
            return CM_SUCCESS;
        }
    }

    if (current_term > candidate_term) {
        *vote_granted = CM_FALSE;
        LOG_DEBUG_INF("[ELC]Not granted to node:%u, current_term(%llu) > candidate_term(%llu)", src_node, current_term,
            candidate_term);
        return CM_SUCCESS;
    }

    log_id_t last_log = stg_last_log_id(stream_id);
    if (elc_check_last_log(&req_vote->last_log, &last_log)) {
        LOG_DEBUG_INF("[ELC]Granted to node:%u, req vote last_log term=%llu index=%llu, local last_log.term=%llu "
            "index=%llu", src_node, req_vote->last_log.term, req_vote->last_log.index, last_log.term, last_log.index);
        *vote_granted = CM_TRUE;
    }
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
    req_vote.send_time = g_timer()->now;
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
    CM_RETURN_IFERR_EX(elc_stream_set_timeout(stream_id, g_timer()->now), elc_stream_unlock(stream_id));
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
    elc_vote_ack_t *ack_vote)
{
    if (role == DCF_ROLE_PRE_CANDIDATE) {
        if (ack_vote->work_mode != elc_stream_get_work_mode(stream_id)) {
            return CM_SUCCESS;
        }
        if (ack_vote->term != current_term) {
            return CM_SUCCESS;
        }
        CM_RETURN_IFERR(proc_node_voting(stream_id, src_node));
        if (!is_win(stream_id)) {
            return CM_SUCCESS;
        }
        LOG_RUN_INF("[ELC]pre-voting succeeded, stream_id=%u, node_id=%u, current_term=%llu",
            stream_id, node_id, current_term);
        CM_RETURN_IFERR(elc_stream_set_timeout(stream_id, g_timer()->now));
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
        CM_RETURN_IFERR(elc_stream_set_hb_ack_time(stream_id, src_node, g_timer()->now));
        CM_RETURN_IFERR(elc_stream_set_role(stream_id, DCF_ROLE_LEADER));
        CM_RETURN_IFERR(elc_hb_req(stream_id, MEC_CMD_HB_REQUEST_RPC_REQ));
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
            date_t date = g_timer()->now - elc_stream_get_elc_timeout_ms() * MICROSECS_PER_MILLISEC;
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

status_t elc_hb_proc(mec_message_t *pack)
{
    uint32 stream_id = pack->head->stream_id;
    uint32 src_node_id = pack->head->src_inst;
    LOG_DEBUG_INF("[ELC]Receive heartbeat from stream_id=%u, node_id=%u", stream_id, src_node_id);
    stat_record(HB_RECV_COUNT, 1);

    elc_hb_t hb_req;
    CM_RETURN_IFERR(elc_decode_hb_req(pack, &hb_req));

    elc_stream_lock_x(stream_id);
    dcf_work_mode_t work_mode = elc_stream_get_work_mode(stream_id);
    if (work_mode == WM_MINORITY && hb_req.work_mode == WM_NORMAL) {
        LOG_DEBUG_INF("[ELC]Ignore heartbeat from node:%u as mismatched work mode, stream_id=%u",
            src_node_id, stream_id);
        elc_stream_unlock(stream_id);
        return CM_SUCCESS;
    }
    status_t ret = elc_stream_refresh_hb_time(stream_id, hb_req.term, hb_req.work_mode, src_node_id);
    elc_stream_unlock(stream_id);
    // send ack
    if (ret == CM_SUCCESS) {
        LOG_DEBUG_INF("[ELC]Send heartbeat ack, stream_id=%u", stream_id);
        ret = elc_hb_ack(stream_id, src_node_id, MEC_CMD_HB_REQUEST_RPC_ACK, hb_req.send_time);
    }
    return ret;
}

static status_t elc_check_md_match_proc(uint32 stream_id, uint32 hb_ack_chksum, date_t now, bool32 *need_md_rep)
{
    date_t last_md_rep_time = elc_stream_get_last_md_rep_time(stream_id);
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

status_t elc_hb_ack_proc(mec_message_t *pack)
{
    uint32 stream_id = pack->head->stream_id;
    uint32 src_node_id = pack->head->src_inst;

    elc_hb_t ack_hb;
    CM_RETURN_IFERR(elc_decode_hb_req(pack, &ack_hb));
    stat_record(HB_RTT, (uint64)(g_timer()->now - ack_hb.send_time));
    LOG_DEBUG_INF("[ELC]Receive heartbeat ack from stream_id=%u, node_id=%u, ack_hb's term:%llu work_mode:%u "
        "md_chksum:%u", stream_id, src_node_id, ack_hb.term, ack_hb.work_mode, ack_hb.md_chksum);

    elc_stream_lock_x(stream_id);
    status_t ret = elc_stream_set_vote_node_work_mode(stream_id, src_node_id, ack_hb.work_mode);
    if (ret != CM_SUCCESS) {
        elc_stream_unlock(stream_id);
        return ret;
    }

    bool32 need_md_rep = CM_FALSE;
    date_t now = g_timer()->now;
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
        if (rep_write(stream_id, md_get_buffer(), size, 0, ENTRY_TYPE_CONF, NULL) != CM_SUCCESS) {
            CM_RETURN_IFERR(md_set_status(META_NORMAL));
            return CM_ERROR;
        }
        CM_RETURN_IFERR(md_set_status(META_NORMAL));
        CM_RETURN_IFERR(elc_stream_set_last_md_rep_time(stream_id, now));
    }
    return ret;
}

status_t elc_hb_req(uint32 stream_id, mec_command_t cmd)
{
    uint32 node_id = elc_stream_get_current_node();
    mec_message_t pack;
    elc_hb_t req_hb;
    req_hb.term = elc_stream_get_current_term(stream_id);
    req_hb.work_mode = elc_stream_get_work_mode(stream_id);
    req_hb.send_time = g_timer()->now;
    CM_RETURN_IFERR(mec_alloc_pack(&pack, cmd, node_id, CM_INVALID_NODE_ID, stream_id));
    if (elc_encode_hb_req(&pack, &req_hb) != CM_SUCCESS) {
        mec_release_pack(&pack);
        LOG_DEBUG_ERR("[ELC]encode failed, when send heartbeat message");
        return CM_ERROR;
    }
    uint64 inst_bits[INSTS_BIT_SZ] = {0};
    uint64 success_inst[INSTS_BIT_SZ];
    if (elc_stream_vote_node_list(stream_id, inst_bits) != CM_SUCCESS) {
        mec_release_pack(&pack);
        LOG_DEBUG_ERR("[ELC]prepare node list failed, when send heartbeat message");
        return CM_ERROR;
    }
    mec_broadcast(stream_id, inst_bits, &pack, success_inst);
    LOG_DEBUG_INF("[ELC]elc heartbeat broadcast, local node_id=%u, heartbeat term=%llu work_mode=%d",
        node_id, req_hb.term, req_hb.work_mode);
    stat_record(HB_SEND_COUNT, 1);
    mec_release_pack(&pack);
    return CM_SUCCESS;
}

static status_t elc_hb_ack(uint32 stream_id, uint32 dst_node, mec_command_t cmd, int64 req_hb_send_time)
{
    mec_message_t pack;
    uint32 src_node = elc_stream_get_current_node();
    elc_hb_t req_hb;
    req_hb.term = elc_stream_get_current_term(stream_id);
    req_hb.work_mode = elc_stream_get_work_mode(stream_id);
    req_hb.md_chksum = md_get_checksum();
    req_hb.send_time = req_hb_send_time;
    CM_RETURN_IFERR(mec_alloc_pack(&pack, cmd, src_node, dst_node, stream_id));

    if (elc_encode_hb_req(&pack, &req_hb) != CM_SUCCESS) {
        mec_release_pack(&pack);
        LOG_DEBUG_ERR("[ELC]encode failed, when send heartbeat ack message");
        return CM_ERROR;
    }
    status_t ret = mec_send_data(&pack);
    LOG_DEBUG_INF("[ELC]Send elc hb ack, term:%llu work_mode:%u md_chksum=%u",
        req_hb.term, req_hb.work_mode, req_hb.md_chksum);
    mec_release_pack(&pack);
    return ret;
}

#ifdef __cplusplus
}
#endif
