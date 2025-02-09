/// Governance model for Julius Coin
#[derive(Debug)]
pub struct Governance {
    pub proposals: Vec<Proposal>,
}

#[derive(Debug)]
pub struct Proposal {
    pub id: u64,
    pub description: String,
    pub votes_for: u64,
    pub votes_against: u64,
}

impl Governance {
    /// Create a new governance model
    pub fn new() -> Self {
        Governance { proposals: Vec::new() }
    }

    /// Add a new proposal
    pub fn add_proposal(&mut self, description: String) -> u64 {
        let id = self.proposals.len() as u64 + 1;
        let proposal = Proposal { id, description, votes_for: 0, votes_against: 0 };
        self.proposals.push(proposal);
        id
    }

    /// Vote on a proposal
    pub fn vote(&mut self, proposal_id: u64, in_favor: bool) {
        if let Some(proposal) = self.proposals.iter_mut().find(|p| p.id == proposal_id) {
            if in_favor {
                proposal.votes_for += 1;
            } else {
                proposal.votes_against += 1;
            }
        }
    }
}
