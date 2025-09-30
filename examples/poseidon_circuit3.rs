use ff::{Field, PrimeField};
use halo2curves::bn256::Fr;
use nova_snark::{
  frontend::{num::AllocatedNum, ConstraintSystem, SynthesisError},
  traits::{circuit::StepCircuit, Group},
};

use crate::circuit_poseidon::{ark, mix, mix_last, sigma, POSEIDON_CONSTANTS};

#[derive(Clone, Debug)]
pub struct PoseidonCircuit3<G: Group> {
  _phantom: std::marker::PhantomData<G>,
}

impl<G: Group> PoseidonCircuit3<G> {
  pub fn new() -> Self {
    Self {
      _phantom: std::marker::PhantomData,
    }
  }
}

impl<G: Group<Scalar = Fr>> StepCircuit<G::Scalar> for PoseidonCircuit3<G> {
  fn arity(&self) -> usize {
    3 // Input: [state0, state1, state2]
  }

  fn synthesize<CS: ConstraintSystem<G::Scalar>>(
    &self,
    cs: &mut CS,
    z_in: &[AllocatedNum<G::Scalar>],
  ) -> Result<Vec<AllocatedNum<G::Scalar>>, SynthesisError> {
    let t = 3;
    let n_rounds_f = 8;
    let n_rounds_p = 57;
    let constants = &*POSEIDON_CONSTANTS;

    println!("Synthesize 3");

    // Extract state from input (first 3 elements)
    let mut state = vec![z_in[0].clone(), z_in[1].clone(), z_in[2].clone()];
    
    // Second half of full rounds
    for r in 0..(n_rounds_f / 2 - 1) {
      for value in &mut state {
        *value = sigma(value, cs)?;
      }
      state = ark(
        t,
        (n_rounds_f / 2 + 1) * t + n_rounds_p + r * t,
        &state,
        &constants.c,
        cs,
      )?;
      state = mix(t, &constants.m, cs, &state)?;
    }

    // Final Round
    state = state
      .iter()
      .map(|val| sigma(val, cs))
      .collect::<Result<Vec<_>, _>>()?;

    // Final MixLast
    let final_result = mix_last(t, &constants.m, cs, &state, 0)?;
    
    println!("Circuit3 final hash: {:?}", final_result[0]);

    // Return: [final_hash, orig_x, orig_y]
    let output = vec![
      final_result[0].clone(), // The final Poseidon hash
      final_result[0].clone(),
      final_result[0].clone()
    ];
    
    Ok(output)
  }
}

fn main() {

}