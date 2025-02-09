/// Main entry point for Julius Coin
fn main() {
    // Initialize logging
    env_logger::init();
    info!("=== Julius Coin MVPの起動 ===");

    // Create a new governance model
    let mut governance = Governance::new();

    // Create a new economic model
    let economic_model = EconomicModel::new(21000000, 50, 0.05);

    // Create a new wallet
    let wallet = Wallet::new();
    wallet.save_to_file("wallet.bin");

    // Load the wallet
    let loaded_wallet = Wallet::load_from_file("wallet.bin");
    assert_eq!(wallet.get_address().hash, loaded_wallet.get_address().hash);

    // Add a proposal
    governance.add_proposal(String::from("Test Proposal"));

    // Display governance proposals
    for proposal in governance.proposals.iter() {
        info!("Proposal ID: {}, Description: {}", proposal.id, proposal.description);
    }
}
