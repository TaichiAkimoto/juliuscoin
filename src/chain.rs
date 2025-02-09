/// Sharding structure for the blockchain
#[derive(Debug)]
pub struct Shard {
    pub id: u64,
    pub blocks: Vec<Block>,
}

/// Sharded blockchain structure
#[derive(Debug)]
pub struct ShardedBlockchain {
    pub shards: Vec<Shard>,
}

impl ShardedBlockchain {
    /// Create a new sharded blockchain
    pub fn new() -> Self {
        ShardedBlockchain { shards: Vec::new() }
    }

    /// Add a new block to a specific shard
    pub fn add_block_to_shard(&mut self, shard_id: u64, block: Block) {
        if let Some(shard) = self.shards.iter_mut().find(|s| s.id == shard_id) {
            shard.blocks.push(block);
        } else {
            let new_shard = Shard { id: shard_id, blocks: vec![block] };
            self.shards.push(new_shard);
        }
    }
}
