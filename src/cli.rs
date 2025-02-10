use clap::{Parser, Subcommand};
use crate::governance::{Governance, JIPType, JIPStatus, VoteType};
use crate::cryptography::crypto::PQAddress;
use crate::cryptography::wallet::{Wallet, Mnemonic, WalletError, EntropySize};
use log::info;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Create a new wallet
    WalletCreate {
        /// Generate with mnemonic phrase
        #[arg(long)]
        mnemonic: bool,

        /// Use 12 words instead of 24 (only with --mnemonic)
        #[arg(long)]
        short_words: bool,

        /// Password to encrypt the wallet
        #[arg(short, long)]
        password: Option<String>,

        /// Optional BIP39 passphrase for additional security
        #[arg(long)]
        passphrase: Option<String>,
    },

    /// Recover a wallet from mnemonic phrase
    WalletRecover {
        /// The mnemonic phrase
        #[arg(long)]
        mnemonic: String,

        /// Password to encrypt the wallet
        #[arg(short, long)]
        password: Option<String>,

        /// Optional BIP39 passphrase for additional security
        #[arg(long)]
        passphrase: Option<String>,
    },

    /// Show wallet information
    WalletInfo,

    /// Backup wallet to a file
    WalletBackup {
        /// Path to save the backup
        #[arg(short, long)]
        path: String,
    },

    /// Restore wallet from a backup file
    WalletRestore {
        /// Path to the backup file
        #[arg(short, long)]
        path: String,

        /// Password to encrypt the restored wallet
        #[arg(short, long)]
        password: Option<String>,
    },

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

        /// 資金調達要求額 (オプション)
        #[arg(short, long)]
        funding: Option<u64>,

        /// 提案デポジット額
        #[arg(short, long)]
        deposit: u64,
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
            Commands::WalletCreate { mnemonic: use_mnemonic, short_words, password, passphrase } => {
                if use_mnemonic {
                    let mnemonic = if short_words {
                        Mnemonic::generate_with_size(EntropySize::Bits128)
                    } else {
                        Mnemonic::generate_with_size(EntropySize::Bits256)
                    };

                    info!("Generated mnemonic phrase: {}", mnemonic.as_str());
                    info!("Word count: {}", mnemonic.word_count());
                    info!("IMPORTANT: Please write down your mnemonic phrase and store it securely!");
                    info!("You will need it to recover your wallet if you lose access.");

                    let mut mnemonic = mnemonic;
                    if let Some(pass) = passphrase {
                        mnemonic.set_passphrase(&pass);
                        info!("BIP39 passphrase set successfully");
                    }
                    
                    let wallet = Wallet::from_mnemonic(&mnemonic)?;
                    if let Some(pass) = password {
                        wallet.save_encrypted(&pass)?;
                        info!("Wallet encrypted and saved successfully");
                    } else {
                        wallet.save()?;
                        info!("Wallet saved successfully");
                    }
                } else {
                    let wallet = Wallet::new()?;
                    if let Some(pass) = password {
                        wallet.save_encrypted(&pass)?;
                        info!("Wallet encrypted and saved successfully");
                    } else {
                        wallet.save()?;
                        info!("Wallet saved successfully");
                    }
                }
                Ok(())
            }

            Commands::WalletRecover { mnemonic: phrase, password, passphrase } => {
                let mut mnemonic = Mnemonic::from_phrase(&phrase)
                    .map_err(|e| format!("Invalid mnemonic phrase: {}", e))?;

                if let Some(pass) = passphrase {
                    mnemonic.set_passphrase(&pass);
                    info!("BIP39 passphrase set successfully");
                }
                
                let wallet = Wallet::from_mnemonic(&mnemonic)?;
                if let Some(pass) = password {
                    wallet.save_encrypted(&pass)?;
                    info!("Wallet recovered and saved with encryption");
                } else {
                    wallet.save()?;
                    info!("Wallet recovered and saved");
                }
                Ok(())
            }

            Commands::WalletInfo => {
                let wallet = Wallet::load("wallet.dat")
                    .map_err(|e| format!("Failed to load wallet: {}", e))?;
                info!("Wallet Address: {}", hex::encode(&wallet.address_hash));
                if let Some(mnemonic) = wallet.get_mnemonic() {
                    info!("Has mnemonic backup: Yes ({} words)", mnemonic.split_whitespace().count());
                } else {
                    info!("Has mnemonic backup: No");
                }
                Ok(())
            }

            Commands::WalletBackup { path } => {
                let wallet = Wallet::load("wallet.dat")
                    .map_err(|e| format!("Failed to load wallet: {}", e))?;
                wallet.backup(&path)?;
                info!("Wallet backed up successfully to: {}", path);
                Ok(())
            }

            Commands::WalletRestore { path, password } => {
                let wallet = Wallet::restore_from_backup(&path)?;
                if let Some(pass) = password {
                    wallet.save_encrypted(&pass)?;
                    info!("Wallet restored and saved with encryption");
                } else {
                    wallet.save()?;
                    info!("Wallet restored and saved");
                }
                Ok(())
            }

            Commands::Propose { title, jip_type, description, funding, deposit } => {
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
                    funding,
                    deposit,
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