use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use crate::cryptography::crypto::PQAddress;
use log;

/// JIP (Julius Improvement Proposal) の状態
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
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
    pub funding_request: Option<u64>,     // Amount of funding requested from treasury
    pub funding_received: Option<u64>,     // Amount of funding received from treasury
    pub proposal_deposit: Option<u64>,     // Deposit locked when proposing (returned on acceptance)
}

/// ガバナンス状態管理
pub struct Governance {
    pub jips: HashMap<u32, JIP>,
    pub next_jip_id: u32,
    pub min_proposal_stake: u64,      // 提案に必要な最小ステーク量
    pub voting_period: u64,           // 投票期間（ブロック数）
    pub approval_threshold: f64,      // 承認に必要な賛成票の割合
    pub min_participation: f64,       // 最小投票参加率
    pub treasury_balance: u64,        // Treasury balance in smallest units
    pub treasury_fee_rate: u64,       // Fee rate in basis points (1/10000)
    pub min_funding_request: u64,     // Minimum amount that can be requested from treasury
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
            treasury_balance: 0,
            treasury_fee_rate: 1000,   // 10% of fees go to treasury by default
            min_funding_request: 1000_000_000, // 1 coin minimum funding request
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
        funding_request: Option<u64>,
        proposal_deposit: u64,
    ) -> Result<u32, &'static str> {
        // 提案に必要なステーク量のチェック
        if author_stake < self.min_proposal_stake {
            return Err("Insufficient stake to make a proposal");
        }

        // Check proposal deposit
        if proposal_deposit < self.min_proposal_stake {
            return Err("Insufficient proposal deposit");
        }

        // Validate funding request if present
        if let Some(request) = funding_request {
            if request < self.min_funding_request {
                return Err("Funding request below minimum amount");
            }
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
            funding_request,
            funding_received: None,
            proposal_deposit: Some(proposal_deposit),
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
        // First, calculate the voting result
        let (new_status, funding_request, proposal_deposit) = {
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
                let deposit = jip.proposal_deposit.take();
                return Ok(JIPStatus::Rejected);
            }

            // 承認判定
            let approval_rate = yes_votes as f64 / total_votes as f64;
            let new_status = if approval_rate >= self.approval_threshold {
                JIPStatus::Accepted
            } else {
                JIPStatus::Rejected
            };

            jip.status = new_status.clone();
            (new_status, jip.funding_request, jip.proposal_deposit.take())
        };

        // Handle proposal deposit and funding based on result
        match new_status {
            JIPStatus::Accepted => {
                // Return proposal deposit on acceptance
                if let Some(deposit) = proposal_deposit {
                    // Here you would implement the logic to return the deposit to the proposer
                    log::info!("Returning proposal deposit of {} to proposer", deposit);
                }

                // If there's a funding request, process it
                if let Some(request) = funding_request {
                    if let Ok(()) = self.fund_jip(jip_id, request) {
                        if let Some(jip) = self.jips.get_mut(&jip_id) {
                            jip.funding_received = Some(request);
                            log::info!("Funded JIP {} with {} coins", jip_id, request as f64 / 1_000_000_000.0);
                        }
                    }
                }
            }
            JIPStatus::Rejected => {
                // Return proposal deposit on rejection
                if let Some(deposit) = proposal_deposit {
                    // Here you would implement the logic to return the deposit to the proposer
                    log::info!("Returning proposal deposit of {} to proposer", deposit);
                }
            }
            _ => {}
        }

        Ok(new_status)
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

    /// Collect fees for the treasury
    pub fn collect_treasury_fees(&mut self, amount: u64) {
        self.treasury_balance = self.treasury_balance.saturating_add(amount);
    }

    /// Request funding from treasury for a JIP
    pub fn fund_jip(&mut self, jip_id: u32, amount: u64) -> Result<(), &'static str> {
        // Check if JIP exists and is in Accepted state
        let jip = self.jips.get_mut(&jip_id)
            .ok_or("JIP not found")?;

        if jip.status != JIPStatus::Accepted {
            return Err("JIP must be in Accepted state to receive funding");
        }

        if amount < self.min_funding_request {
            return Err("Funding request below minimum amount");
        }

        if amount > self.treasury_balance {
            return Err("Insufficient treasury balance");
        }

        // Deduct from treasury
        self.treasury_balance = self.treasury_balance.saturating_sub(amount);

        Ok(())
    }

    /// Get current treasury balance
    pub fn get_treasury_balance(&self) -> u64 {
        self.treasury_balance
    }

    /// Set treasury fee rate (in basis points)
    pub fn set_treasury_fee_rate(&mut self, rate: u64) -> Result<(), &'static str> {
        if rate > 10000 {
            return Err("Fee rate cannot exceed 100%");
        }
        self.treasury_fee_rate = rate;
        Ok(())
    }

    /// Get treasury fee rate
    pub fn get_treasury_fee_rate(&self) -> u64 {
        self.treasury_fee_rate
    }

    /// Update JIP statuses based on current block height
    pub fn update_jip_statuses(&mut self, current_block: u64) {
        // Collect JIPs that need status updates
        let updates: Vec<_> = self.jips.iter()
            .filter_map(|(id, jip)| {
                match jip.status {
                    JIPStatus::Proposed => {
                        if current_block >= jip.created_at + self.voting_period / 4 {
                            Some((*id, JIPStatus::Voting))
                        } else {
                            None
                        }
                    },
                    JIPStatus::Voting => {
                        if let Some(end) = jip.voting_period_end {
                            if current_block > end {
                                Some((*id, JIPStatus::Voting)) // Temporary status, will be updated by tally
                            } else {
                                None
                            }
                        } else {
                            None
                        }
                    },
                    _ => None
                }
            })
            .collect();

        // Apply updates
        for (id, new_status) in updates {
            match new_status {
                JIPStatus::Voting => {
                    if let Some(jip) = self.jips.get_mut(&id) {
                        if jip.status == JIPStatus::Proposed {
                            // Transition from Proposed to Voting
                            jip.status = JIPStatus::Voting;
                            log::info!("JIP {} transitioned to Voting state", id);
                        } else {
                            // Tally votes for JIPs whose voting period ended
                            if let Ok(final_status) = self.tally_votes(id, self.get_total_stake()) {
                                log::info!("JIP {} voting period ended, new status: {:?}", id, final_status);
                            }
                        }
                    }
                },
                _ => {}
            }
        }
    }

    /// Get total stake in the system (this should be provided by the blockchain)
    fn get_total_stake(&self) -> u64 {
        // This should be implemented to get actual total stake from the blockchain
        // For now, return a default value
        1_000_000_000_000 // 1000 coins
    }

    /// Check if a JIP can be funded
    pub fn can_fund_jip(&self, jip_id: u32) -> Result<bool, &'static str> {
        let jip = self.jips.get(&jip_id)
            .ok_or("JIP not found")?;

        // Check if JIP is in correct state
        if jip.status != JIPStatus::Accepted {
            return Ok(false);
        }

        // Check if JIP has already received funding
        if jip.funding_received.is_some() {
            return Ok(false);
        }

        // Check if there's a funding request
        let request = match jip.funding_request {
            Some(amount) => amount,
            None => return Ok(false),
        };

        // Check if treasury has sufficient balance
        if request > self.treasury_balance {
            return Ok(false);
        }

        Ok(true)
    }

    /// Get all JIPs eligible for funding
    pub fn get_fundable_jips(&self) -> Vec<u32> {
        self.jips.iter()
            .filter_map(|(id, _)| {
                match self.can_fund_jip(*id) {
                    Ok(true) => Some(*id),
                    _ => None,
                }
            })
            .collect()
    }

    /// Get treasury statistics
    pub fn get_treasury_stats(&self) -> TreasuryStats {
        let total_requested: u64 = self.jips.values()
            .filter_map(|jip| jip.funding_request)
            .sum();

        let total_funded: u64 = self.jips.values()
            .filter_map(|jip| jip.funding_received)
            .sum();

        TreasuryStats {
            balance: self.treasury_balance,
            total_requested,
            total_funded,
            fee_rate: self.treasury_fee_rate,
        }
    }
}

/// Statistics about the treasury
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TreasuryStats {
    pub balance: u64,
    pub total_requested: u64,
    pub total_funded: u64,
    pub fee_rate: u64,
} 