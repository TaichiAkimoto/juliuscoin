//! Script system for JuliusCoin smart contracts.
//! 
//! This module implements a Bitcoin Script-like system for basic smart contract functionality.
//! The script system is stack-based and supports common cryptographic operations,
//! as well as basic flow control and arithmetic operations.

use sha2::{Sha256, Digest};
use std::collections::VecDeque;
use anyhow::{Result, anyhow};
use serde::{Serialize, Deserialize};
use crate::cryptography::crypto::{verify_signature, derive_address_from_pk};

/// Maximum number of operations allowed in a script
pub const MAX_SCRIPT_OPS: usize = 201;

/// Maximum script size in bytes
pub const MAX_SCRIPT_SIZE: usize = 10000;

/// Maximum number of elements on the stack
pub const MAX_STACK_SIZE: usize = 1000;

/// Script operation codes
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum OpCode {
    // Constants
    OP_0,           // Push empty value onto stack
    OP_1,           // Push 1 onto stack
    OP_2,           // Push 2 onto stack
    OP_3,           // Push 3 onto stack
    OP_4,           // Push 4 onto stack
    OP_5,           // Push 5 onto stack
    OP_16,          // Push 16 onto stack
    OP_FALSE,       // Push false onto stack
    OP_TRUE,        // Push true onto stack
    OP_PUSHDATA,    // Push next bytes onto stack

    // Flow Control
    OP_IF,          // Execute block if top stack value is true
    OP_ELSE,        // Execute block if previous IF was false
    OP_ENDIF,       // End IF block
    OP_VERIFY,      // Mark transaction as invalid if top stack value is false
    OP_RETURN,      // Mark transaction as invalid

    // Stack
    OP_DUP,         // Duplicate top stack item
    OP_DROP,        // Remove top stack item
    OP_SWAP,        // Swap top two stack items
    OP_2DUP,        // Duplicate top two stack items
    OP_2DROP,       // Remove top two stack items
    OP_DEPTH,       // Push stack size onto stack

    // Arithmetic
    OP_ADD,         // Add top two items
    OP_SUB,         // Subtract top item from second top item
    OP_MUL,         // Multiply top two items
    OP_DIV,         // Divide second top item by top item
    OP_MOD,         // Remainder divide second top item by top item
    OP_1ADD,        // Add 1 to top item
    OP_1SUB,        // Subtract 1 from top item

    // Crypto
    OP_SHA256,              // SHA256 hash of top item
    OP_HASH256,            // Double SHA256 hash of top item
    OP_CHECKSIG,           // Verify signature using public key
    OP_CHECKMULTISIG,      // Verify M-of-N multi-signature
    OP_CHECKLOCKTIMEVERIFY, // Verify lock time/block height
    
    // Comparison
    OP_EQUAL,       // Push true if top two items are equal
    OP_EQUALVERIFY, // OP_EQUAL and OP_VERIFY combined
    OP_LESSTHAN,    // Push true if second item is less than top item
    OP_GREATERTHAN, // Push true if second item is greater than top item
}

/// Represents a complete script
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Script {
    /// Raw script bytes
    pub code: Vec<u8>,
}

impl Script {
    /// Create a new empty script
    pub fn new() -> Self {
        Script {
            code: Vec::new(),
        }
    }

    /// Creates a script that can never be spent (used for burning coins)
    pub fn create_unspendable() -> Self {
        let mut script = Self::new();
        script.code = vec![OpCode::OP_FALSE as u8];
        script
    }

    /// Creates a new empty script (alias for new() for backward compatibility)
    pub fn create_empty() -> Self {
        Self::new()
    }

    /// Parse raw bytes into script operations
    pub fn parse(&self) -> Result<Vec<OpCode>> {
        let mut ops = Vec::new();
        let mut i = 0;

        while i < self.code.len() {
            if ops.len() >= MAX_SCRIPT_OPS {
                return Err(anyhow!("Script exceeds maximum operation count"));
            }

            match self.code[i] {
                0x00 => ops.push(OpCode::OP_0),
                0x51 => ops.push(OpCode::OP_1),
                0x52 => ops.push(OpCode::OP_2),
                0x53 => ops.push(OpCode::OP_3),
                0x54 => ops.push(OpCode::OP_4),
                0x55 => ops.push(OpCode::OP_5),
                0x60 => ops.push(OpCode::OP_16),
                0x61 => ops.push(OpCode::OP_FALSE),
                0x62 => ops.push(OpCode::OP_TRUE),
                0x4c => ops.push(OpCode::OP_PUSHDATA),
                0x63 => ops.push(OpCode::OP_IF),
                0x64 => ops.push(OpCode::OP_ELSE),
                0x65 => ops.push(OpCode::OP_ENDIF),
                0x69 => ops.push(OpCode::OP_VERIFY),
                0x6a => ops.push(OpCode::OP_RETURN),
                0x76 => ops.push(OpCode::OP_DUP),
                0x75 => ops.push(OpCode::OP_DROP),
                0x7c => ops.push(OpCode::OP_SWAP),
                0x6e => ops.push(OpCode::OP_2DUP),
                0x6d => ops.push(OpCode::OP_2DROP),
                0x74 => ops.push(OpCode::OP_DEPTH),
                0x93 => ops.push(OpCode::OP_ADD),
                0x94 => ops.push(OpCode::OP_SUB),
                0x95 => ops.push(OpCode::OP_MUL),
                0x96 => ops.push(OpCode::OP_DIV),
                0x97 => ops.push(OpCode::OP_MOD),
                0x8b => ops.push(OpCode::OP_1ADD),
                0x8c => ops.push(OpCode::OP_1SUB),
                0xa8 => ops.push(OpCode::OP_SHA256),
                0xaa => ops.push(OpCode::OP_HASH256),
                0xac => ops.push(OpCode::OP_CHECKSIG),
                0xae => ops.push(OpCode::OP_CHECKMULTISIG),
                0xb1 => ops.push(OpCode::OP_CHECKLOCKTIMEVERIFY),
                0x87 => ops.push(OpCode::OP_EQUAL),
                0x88 => ops.push(OpCode::OP_EQUALVERIFY),
                0x9f => ops.push(OpCode::OP_LESSTHAN),
                0xa0 => ops.push(OpCode::OP_GREATERTHAN),
                _ => return Err(anyhow!("Invalid opcode: {}", self.code[i])),
            }
            i += 1;
        }

        Ok(ops)
    }

    /// Execute the script with the given stack
    pub fn execute(&self, mut stack: VecDeque<Vec<u8>>, block_height: u64) -> Result<bool, String> {
        if self.code.len() > MAX_SCRIPT_SIZE {
            return Err("Script exceeds maximum size".to_string());
        }

        let ops = self.parse().map_err(|e| e.to_string())?;
        let mut i = 0;

        while i < ops.len() {
            if stack.len() > MAX_STACK_SIZE {
                return Err("Stack size exceeded".to_string());
            }

            match ops[i] {
                OpCode::OP_0 => stack.push_front(vec![]),
                OpCode::OP_1 => stack.push_front(vec![1]),
                OpCode::OP_2 => stack.push_front(vec![2]),
                OpCode::OP_3 => stack.push_front(vec![3]),
                OpCode::OP_4 => stack.push_front(vec![4]),
                OpCode::OP_5 => stack.push_front(vec![5]),
                OpCode::OP_16 => stack.push_front(vec![16]),
                OpCode::OP_FALSE => stack.push_front(vec![0]),
                OpCode::OP_TRUE => stack.push_front(vec![1]),
                
                OpCode::OP_DUP => {
                    if let Some(top) = stack.front() {
                        stack.push_front(top.clone());
                    } else {
                        return Err("Stack underflow".to_string());
                    }
                },

                OpCode::OP_HASH256 => {
                    if let Some(data) = stack.pop_front() {
                        let mut hasher = Sha256::new();
                        hasher.update(&data);
                        let result = hasher.finalize();
                        let mut hasher2 = Sha256::new();
                        hasher2.update(&result);
                        stack.push_front(hasher2.finalize().to_vec());
                    } else {
                        return Err("Stack underflow".to_string());
                    }
                },

                OpCode::OP_CHECKSIG => {
                    if stack.len() < 2 {
                        return Err("Stack underflow".to_string());
                    }
                    let pubkey = stack.pop_front().unwrap();
                    let sig = stack.pop_front().unwrap();
                    
                    // Use the system's verify_signature function
                    let valid = verify_signature(&pubkey, &sig, &[]);
                    stack.push_front(vec![if valid { 1 } else { 0 }]);
                },

                OpCode::OP_CHECKLOCKTIMEVERIFY => {
                    if let Some(locktime) = stack.front() {
                        let lock_height = u64::from_be_bytes(locktime.clone().try_into().map_err(|_| "Invalid locktime")?);
                        if block_height < lock_height {
                            return Err(format!("Block height {} is below required height {}", block_height, lock_height));
                        }
                    } else {
                        return Err("Stack underflow".to_string());
                    }
                },

                OpCode::OP_VERIFY => {
                    if let Some(top) = stack.pop_front() {
                        if top.is_empty() || (top.len() == 1 && top[0] == 0) {
                            return Ok(false);
                        }
                    } else {
                        return Err("Stack underflow".to_string());
                    }
                },

                OpCode::OP_RETURN => return Ok(false),

                _ => return Err(format!("Unimplemented opcode: {:?}", ops[i])),
            }
            i += 1;
        }

        // Script is valid if stack is not empty and top value is true
        Ok(!stack.is_empty() && !stack.front().unwrap().is_empty() && stack.front().unwrap()[0] != 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_p2pkh_script() {
        let mut script = Script::new();
        script.code = vec![
            0x76, // OP_DUP
            0xa8, // OP_SHA256
            0x88, // OP_EQUALVERIFY
            0xac, // OP_CHECKSIG
        ];

        let mut stack = VecDeque::new();
        stack.push_front(vec![1; 32]); // Dummy public key
        stack.push_front(vec![2; 64]); // Dummy signature

        let result = script.execute(stack, 0);
        assert!(result.is_ok());
    }

    #[test]
    fn test_timelock_script() {
        let mut script = Script::new();
        script.code = vec![
            0xb1, // OP_CHECKLOCKTIMEVERIFY
            0x69, // OP_VERIFY
        ];

        let mut stack = VecDeque::new();
        stack.push_front(100u64.to_be_bytes().to_vec());

        // Should fail if block height is less than locktime
        let result = script.execute(stack.clone(), 99);
        assert!(result.is_err());

        // Should succeed if block height is equal or greater
        let result = script.execute(stack.clone(), 100);
        assert!(result.is_ok());
    }
} 