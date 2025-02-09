/// Testing and validation module for Julius Coin
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wallet_creation() {
        let wallet = Wallet::new();
        assert_eq!(wallet.public_key.len() > 0, true);
        assert_eq!(wallet.secret_key.len() > 0, true);
        assert_eq!(wallet.address_hash.len() > 0, true);
    }

    #[test]
    fn test_governance_proposal() {
        let mut governance = Governance::new();
        let proposal_id = governance.add_proposal(String::from("Test Proposal"));
        assert_eq!(governance.proposals.len(), 1);
        assert_eq!(governance.proposals[0].id, proposal_id);
    }

    #[test]
    fn test_economic_model() {
        let economic_model = EconomicModel::new(21000000, 50, 0.05);
        let new_supply = economic_model.calculate_new_supply(1);
        assert_eq!(new_supply, 50);
    }
}
