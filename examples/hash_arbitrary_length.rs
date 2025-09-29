use ff::{Field, PrimeField};
use halo2curves::bn256::Fr;
use nova_snark::{
  frontend::{num::AllocatedNum, ConstraintSystem, SynthesisError},
  nova::{PublicParams, RecursiveSNARK},
  provider::{Bn256EngineKZG, GrumpkinEngine},
  traits::{circuit::StepCircuit, snark::RelaxedR1CSSNARKTrait, Engine, Group},
};

mod circuit_poseidon;
use circuit_poseidon::hasher;

type E1 = Bn256EngineKZG;
type E2 = GrumpkinEngine;
type EE1 = nova_snark::provider::hyperkzg::EvaluationEngine<E1>;
type EE2 = nova_snark::provider::ipa_pc::EvaluationEngine<E2>;
type S1 = nova_snark::spartan::snark::RelaxedR1CSSNARK<E1, EE1>;
type S2 = nova_snark::spartan::snark::RelaxedR1CSSNARK<E2, EE2>;

#[derive(Clone, Debug)]
struct PoseidonHashCircuit<G: Group> {
  data: Vec<G::Scalar>, // Data to hash: [1, 2]
}

impl<G: Group> PoseidonHashCircuit<G> {
  fn new(data: Vec<G::Scalar>) -> Self {
    Self { data }
  }
}

impl<G: Group<Scalar = Fr>> StepCircuit<G::Scalar> for PoseidonHashCircuit<G> {
  fn arity(&self) -> usize {
    1 // Returns just the hash
  }

  // Simple sponge: [0, 0, 0] + [1, 2] → hash
  fn synthesize<CS: ConstraintSystem<G::Scalar>>(
    &self,
    cs: &mut CS,
    z_in: &[AllocatedNum<G::Scalar>], // [dummy_input] - not used
  ) -> Result<Vec<AllocatedNum<G::Scalar>>, SynthesisError> {
    // Initialize sponge state: [0, 0, 0]
    let zero = AllocatedNum::alloc(cs.namespace(|| "zero"), || Ok(Fr::zero()))?;
    let mut state = vec![zero.clone(), zero.clone(), zero.clone()];

    // Absorb data into rate portion (positions 1 and 2)
    for (i, &data_val) in self.data.iter().enumerate() {
      if i < 2 { // rate = 2 (positions 1,2)
        let data_alloc = AllocatedNum::alloc(cs.namespace(|| format!("data_{}", i)), || Ok(data_val))?;
        state[i + 1] = state[i + 1].add(cs.namespace(|| format!("absorb_{}", i)), &data_alloc)?;
      }
    }
    // Now state = [0, 1, 2]

    // Apply full Poseidon permutation
    let permuted_state = permutation(&state, cs)?;

    // Squeeze phase: apply mix_last to extract final hash
    let constants = &*circuit_poseidon::POSEIDON_CONSTANTS;
    let final_hash = circuit_poseidon::mix_last(3, &constants.m, cs, &permuted_state, 0)?;
    
    Ok(final_hash) // Returns [hash]
  }
}

fn permutation<CS: ConstraintSystem<Fr>>(
  state: &[AllocatedNum<Fr>],
  cs: &mut CS,
) -> Result<Vec<AllocatedNum<Fr>>, SynthesisError> {
  let t = 3;
  let n_rounds_f = 8;
  let n_rounds_p = 57;

  // Import constants from circuit_poseidon module
  let constants = &*circuit_poseidon::POSEIDON_CONSTANTS;

  // Start with the provided state (no need to create [0, x, y])
  let mut current_state = state.to_vec();

  // Initial Ark
  current_state = circuit_poseidon::ark(t, 0, &current_state, &constants.c, cs)?;

  // First half of full rounds
  for r in 0..(n_rounds_f / 2 - 1) {
    for value in &mut current_state {
      *value = circuit_poseidon::sigma(value, cs)?;
    }
    current_state = circuit_poseidon::ark(t, (r + 1) * t, &current_state, &constants.c, cs)?;
    current_state = circuit_poseidon::mix(t, &constants.m, cs, &current_state)?;
  }

  // Middle round
  current_state = current_state
    .iter()
    .map(|val| circuit_poseidon::sigma(val, cs))
    .collect::<Result<Vec<_>, _>>()?;
  current_state = circuit_poseidon::ark(t, (n_rounds_f / 2) * t, &current_state, &constants.c, cs)?;
  current_state = circuit_poseidon::mix(t, &constants.p, cs, &current_state)?;

  // Partial rounds
  for r in 0..n_rounds_p {
    let sigma_result = circuit_poseidon::sigma(&current_state[0], cs)?;
    let constant = AllocatedNum::alloc(cs.namespace(|| format!("partial_const_{}", r)), || {
      Ok(constants.c[(n_rounds_f / 2 + 1) * t + r])
    })?;
    let first = sigma_result.add(cs.namespace(|| format!("partial_add_{}", r)), &constant)?;
    current_state = circuit_poseidon::mix_s(
      t,
      r,
      &constants.s,
      cs,
      &[vec![first], current_state[1..].to_vec()].concat(),
    )?;
  }

  // Second half of full rounds
  for r in 0..(n_rounds_f / 2 - 1) {
    for value in &mut current_state {
      *value = circuit_poseidon::sigma(value, cs)?;
    }
    current_state = circuit_poseidon::ark(
      t,
      (n_rounds_f / 2 + 1) * t + n_rounds_p + r * t,
      &current_state,
      &constants.c,
      cs,
    )?;
    current_state = circuit_poseidon::mix(t, &constants.m, cs, &current_state)?;
  }

  // Final Round
  current_state = current_state
    .iter()
    .map(|val| circuit_poseidon::sigma(val, cs))
    .collect::<Result<Vec<_>, _>>()?;

  Ok(current_state)
}

fn hash_example() -> Result<(), Box<dyn std::error::Error>> {
  let numbers = vec![1, 2];
  println!("Simple sponge hashing: {:?}", numbers);

  // Convert to Fr
  let data_fr: Vec<Fr> = numbers.iter().map(|&x| Fr::from_u128(x)).collect();
  let circuit = PoseidonHashCircuit::new(data_fr);

  let pp = PublicParams::<E1, E2, PoseidonHashCircuit<<E1 as Engine>::GE>>::setup(
    &circuit,
    &*S1::ck_floor(),
    &*S2::ck_floor(),
  )?;

  // Initial state (dummy input)
  let z0 = vec![Fr::zero()];

  let mut recursive_snark = RecursiveSNARK::new(&pp, &circuit, &z0)?;
  println!("Computing hash...");
  
  // Single step: absorb [1,2] into [0,0,0] → permutation → squeeze
  recursive_snark.prove_step(&pp, &circuit)?;

  let final_state = recursive_snark.verify(&pp, 1, &z0)?;
  let final_hash = final_state[0];

  println!("Final sponge hash: {:?}", final_hash);
  Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
  hash_example()?;
  Ok(())
}
