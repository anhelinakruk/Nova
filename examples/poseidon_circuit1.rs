use ff::{Field, PrimeField};
use halo2curves::bn256::Fr;
use nova_snark::{
  frontend::{num::AllocatedNum, ConstraintSystem, SynthesisError},
  traits::{circuit::StepCircuit, Group},
};

use crate::circuit_poseidon::{ark, mix, sigma, POSEIDON_CONSTANTS};

#[derive(Clone, Debug)]
pub struct PoseidonCircuit1<G: Group> {
  _phantom: std::marker::PhantomData<G>,
}

impl<G: Group> PoseidonCircuit1<G> {
  pub fn new() -> Self {
    Self {
      _phantom: std::marker::PhantomData,
    }
  }
}

impl<G: Group<Scalar = Fr>> StepCircuit<G::Scalar> for PoseidonCircuit1<G> {
  fn arity(&self) -> usize {
    3
  }

  fn synthesize<CS: ConstraintSystem<G::Scalar>>(
    &self,
    cs: &mut CS,
    z_in: &[AllocatedNum<G::Scalar>],
  ) -> Result<Vec<AllocatedNum<G::Scalar>>, SynthesisError> {
    let t = 3;
    let n_rounds_f = 8;
    let constants = &*POSEIDON_CONSTANTS;

    println!("Synthesize");

    // Create initial state [0, x, y] where x,y come from input
    let zero = AllocatedNum::alloc(cs.namespace(|| "zero_initial"), || Ok(Fr::zero()))?;
    let mut state = vec![zero, z_in[1].clone(), z_in[2].clone()];
    println!("State 0");

    // Initial Ark (round 0)
    state = ark(t, 0, &state, &constants.c, cs)?;
    println!("ARK: {:?}", state);

    // First half of full rounds
    for r in 0..(n_rounds_f / 2 - 1) {
    for value in &mut state {
      *value = sigma(value, cs)?;
    }
    state = ark(t, (r + 1) * t, &state, &constants.c, cs)?;
    state = mix(t, &constants.m, cs, &state)?;
  }

    // Return: [state0, state1, state2]
    println!("Circuit1 output state: [{:?}, {:?}, {:?}]",state[0], state[1], state[2]);
    
    Ok(state)
  }
}

fn main() {

}