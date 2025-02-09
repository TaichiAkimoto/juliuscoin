use clap::{Parser, Subcommand};
use crate::governance::governance::{Governance, JIPType, JIPStatus, VoteType};
use crate::cryptography::crypto::PQAddress;
use log::info;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// JIPの提案
    Propose {
        /// 提案のタイトル
        #[arg(short, long)]
        title: String,

        /// 提案の種類 (Core/Network/Interface/Meta)
        #[arg(short, long)]
        jip_type: String,

        /// 提案の説明
        #[arg(short, long)]
        description: String,
    },

    /// JIPへの投票
    Vote {
        /// JIP ID
        #[arg(short, long)]
        jip_id: u32,

        /// 投票の種類 (Yes/No/Abstain)
        #[arg(short, long)]
        vote: String,
    },

    /// JIPの一覧表示
    List {
        /// ステータスでフィルタ (オプション)
        #[arg(short, long)]
        status: Option<String>,
    },

    /// JIPの詳細表示
    Show {
        /// JIP ID
        #[arg(short, long)]
        jip_id: u32,
    },
}

pub struct CliHandler {
    governance: Governance,
    wallet: PQAddress,
    current_block: u64,
}

impl CliHandler {
    pub fn new(governance: Governance, wallet: PQAddress, current_block: u64) -> Self {
        Self {
            governance,
            wallet,
            current_block,
        }
    }

    pub fn handle_command(&mut self, args: Vec<String>) -> Result<(), String> {
        let cli = Cli::parse_from(args);

        match cli.command {
            Commands::Propose { title, jip_type, description } => {
                let jip_type = match jip_type.to_lowercase().as_str() {
                    "core" => JIPType::Core,
                    "network" => JIPType::Network,
                    "interface" => JIPType::Interface,
                    "meta" => JIPType::Meta,
                    _ => return Err("Invalid JIP type".to_string()),
                };

                match self.governance.propose_jip(
                    title,
                    self.wallet.clone(),
                    jip_type,
                    description,
                    1000000, // TODO: Get actual stake amount
                    self.current_block,
                ) {
                    Ok(jip_id) => {
                        info!("JIP proposed successfully with ID: {}", jip_id);
                        Ok(())
                    }
                    Err(e) => Err(e.to_string()),
                }
            }

            Commands::Vote { jip_id, vote } => {
                let vote_type = match vote.to_lowercase().as_str() {
                    "yes" => VoteType::Yes,
                    "no" => VoteType::No,
                    "abstain" => VoteType::Abstain,
                    _ => return Err("Invalid vote type".to_string()),
                };

                match self.governance.vote(
                    jip_id,
                    &self.wallet.hash,
                    vote_type,
                    1000, // TODO: Get actual stake amount
                    self.current_block,
                ) {
                    Ok(_) => {
                        info!("Vote recorded successfully");
                        Ok(())
                    }
                    Err(e) => Err(e.to_string()),
                }
            }

            Commands::List { status } => {
                let filter_status = status.map(|s| match s.to_lowercase().as_str() {
                    "draft" => JIPStatus::Draft,
                    "proposed" => JIPStatus::Proposed,
                    "voting" => JIPStatus::Voting,
                    "accepted" => JIPStatus::Accepted,
                    "rejected" => JIPStatus::Rejected,
                    "implemented" => JIPStatus::Implemented,
                    _ => JIPStatus::Proposed, // デフォルト
                });

                info!("=== JIP一覧 ===");
                for (id, jip) in &self.governance.jips {
                    if let Some(ref status) = filter_status {
                        if !std::mem::discriminant(&jip.status)
                            .eq(&std::mem::discriminant(status)) {
                            continue;
                        }
                    }

                    info!(
                        "JIP #{}: {} ({:?}) - {:?}",
                        id, jip.title, jip.jip_type, jip.status
                    );
                }
                Ok(())
            }

            Commands::Show { jip_id } => {
                if let Some(jip) = self.governance.jips.get(&jip_id) {
                    info!("=== JIP #{} ===", jip_id);
                    info!("Title: {}", jip.title);
                    info!("Type: {:?}", jip.jip_type);
                    info!("Status: {:?}", jip.status);
                    info!("Author: {:?}", hex::encode(&jip.author.hash));
                    info!("Created at block: {}", jip.created_at);
                    if let Some(end) = jip.voting_period_end {
                        info!("Voting ends at block: {}", end);
                    }
                    info!("\nDescription:\n{}", jip.description);

                    // 投票状況の表示
                    let mut yes_votes = 0u64;
                    let mut no_votes = 0u64;
                    let mut abstain_votes = 0u64;

                    for (_, (vote, stake)) in &jip.votes {
                        match vote {
                            VoteType::Yes => yes_votes += stake,
                            VoteType::No => no_votes += stake,
                            VoteType::Abstain => abstain_votes += stake,
                        }
                    }

                    info!("\nVoting Status:");
                    info!("Yes: {} coins", yes_votes);
                    info!("No: {} coins", no_votes);
                    info!("Abstain: {} coins", abstain_votes);

                    Ok(())
                } else {
                    Err(format!("JIP {} not found", jip_id))
                }
            }
        }
    }
} 