use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use crate::cryptography::crypto::PQAddress;

/// JIP (Julius Improvement Proposal) の状態
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum JIPStatus {
    Draft,
    Proposed,
    Voting,
    Accepted,
    Rejected,
    Implemented,
}

/// JIP の種類
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum JIPType {
    Core,      // コアプロトコルの変更
    Network,   // P2Pネットワークの変更
    Interface, // APIやインターフェースの変更
    Meta,      // プロセスや組織に関する変更
}

/// 投票の種類
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VoteType {
    Yes,
    No,
    Abstain,
}

/// JIP構造体
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JIP {
    pub id: u32,
    pub title: String,
    pub author: PQAddress,
    pub status: JIPStatus,
    pub jip_type: JIPType,
    pub description: String,
    pub created_at: u64,
    pub voting_period_end: Option<u64>,
    pub votes: HashMap<Vec<u8>, (VoteType, u64)>, // (投票者のアドレスハッシュ => (投票内容, ステーク量))
    pub implementation_block: Option<u64>,
}

/// ガバナンス状態管理
pub struct Governance {
    pub jips: HashMap<u32, JIP>,
    pub next_jip_id: u32,
    pub min_proposal_stake: u64,      // 提案に必要な最小ステーク量
    pub voting_period: u64,           // 投票期間（ブロック数）
    pub approval_threshold: f64,      // 承認に必要な賛成票の割合
    pub min_participation: f64,       // 最小投票参加率
}

impl Governance {
    pub fn new(min_proposal_stake: u64, voting_period: u64) -> Self {
        Self {
            jips: HashMap::new(),
            next_jip_id: 0,
            min_proposal_stake,
            voting_period,
            approval_threshold: 0.66,  // 66%の賛成で承認
            min_participation: 0.40,   // 40%以上の参加が必要
        }
    }

    /// 新しいJIPの提案
    pub fn propose_jip(
        &mut self,
        title: String,
        author: PQAddress,
        jip_type: JIPType,
        description: String,
        author_stake: u64,
        current_block: u64,
    ) -> Result<u32, &'static str> {
        // 提案に必要なステーク量のチェック
        if author_stake < self.min_proposal_stake {
            return Err("Insufficient stake to make a proposal");
        }

        let jip = JIP {
            id: self.next_jip_id,
            title,
            author,
            status: JIPStatus::Proposed,
            jip_type,
            description,
            created_at: current_block,
            voting_period_end: Some(current_block + self.voting_period),
            votes: HashMap::new(),
            implementation_block: None,
        };

        self.jips.insert(self.next_jip_id, jip);
        self.next_jip_id += 1;

        Ok(self.next_jip_id - 1)
    }

    /// JIPへの投票
    pub fn vote(
        &mut self,
        jip_id: u32,
        voter: &[u8],
        vote: VoteType,
        stake: u64,
        current_block: u64,
    ) -> Result<(), &'static str> {
        let jip = self.jips.get_mut(&jip_id)
            .ok_or("JIP not found")?;

        // 投票期間のチェック
        if let Some(end) = jip.voting_period_end {
            if current_block > end {
                return Err("Voting period has ended");
            }
        } else {
            return Err("JIP is not in voting state");
        }

        // 投票を記録
        jip.votes.insert(voter.to_vec(), (vote, stake));
        Ok(())
    }

    /// 投票結果の集計とJIPのステータス更新
    pub fn tally_votes(&mut self, jip_id: u32, total_stake: u64) -> Result<JIPStatus, &'static str> {
        let jip = self.jips.get_mut(&jip_id)
            .ok_or("JIP not found")?;

        let mut yes_votes = 0u64;
        let mut no_votes = 0u64;
        let mut total_votes = 0u64;

        // 投票を集計
        for (_, (vote, stake)) in &jip.votes {
            match vote {
                VoteType::Yes => yes_votes += stake,
                VoteType::No => no_votes += stake,
                VoteType::Abstain => {},
            }
            total_votes += stake;
        }

        // 最小参加率のチェック
        let participation_rate = total_votes as f64 / total_stake as f64;
        if participation_rate < self.min_participation {
            jip.status = JIPStatus::Rejected;
            return Ok(JIPStatus::Rejected);
        }

        // 承認判定
        let approval_rate = yes_votes as f64 / total_votes as f64;
        jip.status = if approval_rate >= self.approval_threshold {
            JIPStatus::Accepted
        } else {
            JIPStatus::Rejected
        };

        Ok(jip.status.clone())
    }

    /// JIPの実装完了を記録
    pub fn mark_implemented(&mut self, jip_id: u32, block: u64) -> Result<(), &'static str> {
        let jip = self.jips.get_mut(&jip_id)
            .ok_or("JIP not found")?;

        if let JIPStatus::Accepted = jip.status {
            jip.status = JIPStatus::Implemented;
            jip.implementation_block = Some(block);
            Ok(())
        } else {
            Err("JIP must be accepted before implementation")
        }
    }
} 