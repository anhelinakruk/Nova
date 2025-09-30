use ff::{Field, PrimeField, WithSmallOrderMulGroup};
use halo2curves::bn256::Fr;
use nova_snark::{
  nova::{PublicParams, RecursiveSNARK},
  provider::{Bn256EngineKZG, GrumpkinEngine},
  traits::{snark::RelaxedR1CSSNARKTrait, Engine},
};

mod circuit_poseidon;
mod poseidon_circuit1;
mod poseidon_circuit2;
mod poseidon_circuit3;

use poseidon_circuit1::PoseidonCircuit1;
use poseidon_circuit2::PoseidonCircuit2;
use poseidon_circuit3::PoseidonCircuit3;

type E1 = Bn256EngineKZG;
type E2 = GrumpkinEngine;
type EE1 = nova_snark::provider::hyperkzg::EvaluationEngine<E1>;
type EE2 = nova_snark::provider::ipa_pc::EvaluationEngine<E2>;
type S1 = nova_snark::spartan::snark::RelaxedR1CSSNARK<E1, EE1>;
type S2 = nova_snark::spartan::snark::RelaxedR1CSSNARK<E2, EE2>;

fn test_folding_poseidon() -> Result<(), Box<dyn std::error::Error>> {
  // Original input values
  let x = Fr::from(1u64);
  let y = Fr::from(2u64);
  println!("Input: x {:?}, y {:?}", x, y);

  // Circuit 1
  println!("\nCircuit 1");
  let circuit1 = PoseidonCircuit1::new();
  
  let pp1 = PublicParams::<E1, E2, PoseidonCircuit1<<E1 as Engine>::GE>>::setup(
    &circuit1,
    &*S1::ck_floor(),
    &*S2::ck_floor(),
  )?;
  
  let z1_in = vec![Fr::ZERO, x, y];
  let mut recursive_snark1 = RecursiveSNARK::new(&pp1, &circuit1, &z1_in)?;
  println!("Rec snark");
  recursive_snark1.prove_step(&pp1, &circuit1)?;
  println!("After prove");
  let z1_out = recursive_snark1.verify(&pp1, 1, &z1_in)?;
  
  println!("Circuit1 output: state = [{:?}, {:?}, {:?}]", 
           z1_out[0], z1_out[1], z1_out[2]);

  // Circuit 2
  println!("\nCircuit 2 ");
  let circuit2 = PoseidonCircuit2::new();
  
  let pp2 = PublicParams::<E1, E2, PoseidonCircuit2<<E1 as Engine>::GE>>::setup(
    &circuit2,
    &*S1::ck_floor(),
    &*S2::ck_floor(),
  )?;
  
  // Use output from circuit1 as input to circuit2
  let z2_in = z1_out;
  println!("State after 1 circiuts: {:?}", z2_in);
  let mut recursive_snark2 = RecursiveSNARK::new(&pp2, &circuit2, &z2_in)?;
  recursive_snark2.prove_step(&pp2, &circuit2)?;
  let z2_out = recursive_snark2.verify(&pp2, 1, &z2_in)?;
  
  println!("Circuit2 output: state = [{:?}, {:?}, {:?}]", 
           z2_out[0], z2_out[1], z2_out[2]);

  //Circuit 3
  println!("\nCircuit 3");
  let circuit3 = PoseidonCircuit3::new();
  
  let pp3 = PublicParams::<E1, E2, PoseidonCircuit3<<E1 as Engine>::GE>>::setup(
    &circuit3,
    &*S1::ck_floor(),
    &*S2::ck_floor(),
  )?;
  
  // Use output from circuit2 as input to circuit3
  let z3_in = z2_out;
  let mut recursive_snark3 = RecursiveSNARK::new(&pp3, &circuit3, &z3_in)?;
  recursive_snark3.prove_step(&pp3, &circuit3)?;
  let z3_out = recursive_snark3.verify(&pp3, 1, &z3_in)?;
  
  let final_hash = z3_out[0];
  println!("Circuit3 output: final_hash = {:?}, original_inputs = [{:?}, {:?}]", 
           final_hash, z3_out[1], z3_out[2]);

  // Import the original circuit for comparison
  use circuit_poseidon::PoseidonCircuit;
  let original_circuit = PoseidonCircuit::new();
  
  let pp_orig = PublicParams::<E1, E2, PoseidonCircuit>::setup(
    &original_circuit,
    &*S1::ck_floor(),
    &*S2::ck_floor(),
  )?;
  
  let z_orig_in = vec![x, y];
  let mut recursive_snark_orig = RecursiveSNARK::new(&pp_orig, &original_circuit, &z_orig_in)?;
  recursive_snark_orig.prove_step(&pp_orig, &original_circuit)?;
  let z_orig_out = recursive_snark_orig.verify(&pp_orig, 1, &z_orig_in)?;
  
  let original_hash = z_orig_out[0];
  println!("Original single circuit hash: {:?}", original_hash);
  
  // === Verification ===
  println!("\n=== VERIFICATION ===");
  let hashes_match = final_hash == original_hash;
  println!("Folded hash:    {:?}", final_hash);
  println!("Original hash:  {:?}", original_hash);
  println!("Hashes match:   {}", hashes_match);
  
  if hashes_match {
    println!("✅ SUCCESS: Folding produces the same hash as the original circuit!");
  } else {
    println!("❌ FAILURE: Folding produces a different hash!");
  }
  
  Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
  test_folding_poseidon()
}