use crate::blockchain::consensus::vdf::{SimpleVDF, WesolowskiVDF, VDFProof};
use crate::blockchain::consensus::staking::PoSState;
use vrf::openssl::CipherSuite;
use vrf::VRF;
use sha2::{Sha256, Digest};

#[test]
fn test_simple_vdf_integration() {
    // Create a new PoS state
    let mut pos_state = PoSState::new().unwrap();
    
    // Enable VDF
    pos_state.use_vdf = true;
    pos_state.vdf_iterations = 1000;
    
    // Create a test input
    let input = b"test input for VDF";
    
    // Generate VDF proof
    let vdf_proof = pos_state.generate_vdf_proof(input).unwrap();
    
    // Verify the proof
    assert!(pos_state.verify_vdf_proof(&vdf_proof));
    
    // Test with invalid proof
    let mut invalid_proof = vdf_proof.clone();
    invalid_proof.output[0] ^= 1; // Flip a bit
    assert!(!pos_state.verify_vdf_proof(&invalid_proof));
}

#[test]
fn test_vdf_disabled() {
    // Create a new PoS state with VDF disabled
    let mut pos_state = PoSState::new().unwrap();
    pos_state.use_vdf = false;
    
    // Attempt to generate VDF proof
    let result = pos_state.generate_vdf_proof(b"test input");
    
    // Should return an error since VDF is disabled
    assert!(result.is_err());
}

#[test]
fn test_vdf_with_vrf() {
    // Create a new PoS state
    let mut pos_state = PoSState::new().unwrap();
    
    // Enable VDF
    pos_state.use_vdf = true;
    pos_state.vdf_iterations = 500; // Use a smaller value for testing
    
    // Initialize VRF
    assert!(pos_state.initialize_vrf().is_ok());
    
    // Generate VRF output
    let vrf = pos_state.vrf.as_mut().unwrap();
    let seed = b"test seed";
    let vrf_proof = vrf.prove(seed, seed).unwrap();
    let vrf_hash = vrf.proof_to_hash(&vrf_proof).unwrap();
    
    // Generate VDF proof using VRF output
    let vdf_proof = pos_state.generate_vdf_proof(&vrf_hash).unwrap();
    
    // Verify the proof
    assert!(pos_state.verify_vdf_proof(&vdf_proof));
    
    // The VDF output should be different from the VRF output
    assert_ne!(vrf_hash, vdf_proof.output);
}

#[test]
fn test_vdf_performance() {
    // Test different iteration counts to measure performance
    let iterations = [100, 500, 1000];
    
    for &iter in &iterations {
        let vdf = SimpleVDF::new(iter);
        let input = b"performance test input";
        
        // Measure generation time
        let start = std::time::Instant::now();
        let proof = vdf.generate(input);
        let gen_time = start.elapsed();
        
        // Measure verification time
        let start = std::time::Instant::now();
        assert!(vdf.verify(&proof));
        let verify_time = start.elapsed();
        
        println!("SimpleVDF with {} iterations:", iter);
        println!("  Generation time: {:?}", gen_time);
        println!("  Verification time: {:?}", verify_time);
    }
}
