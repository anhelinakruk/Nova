use ff::{Field, PrimeField};
use halo2curves::bn256::Fr;
use nova_snark::{
  frontend::{num::AllocatedNum, ConstraintSystem, SynthesisError},
  traits::{circuit::StepCircuit, Group},
};

use crate::circuit_poseidon::{ark, mix, mix_s, sigma, POSEIDON_CONSTANTS};

#[derive(Clone, Debug)]
pub struct PoseidonCircuit2<G: Group> {
  _phantom: std::marker::PhantomData<G>,
}

impl<G: Group> PoseidonCircuit2<G> {
  pub fn new() -> Self {
    Self {
      _phantom: std::marker::PhantomData,
    }
  }
}

impl<G: Group<Scalar = Fr>> StepCircuit<G::Scalar> for PoseidonCircuit2<G> {
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

    println!("Synthesize 2");

    // Extract state from input (first 3 elements)
    let mut state = vec![z_in[0].clone(), z_in[1].clone(), z_in[2].clone()];
    
    // Middle round
    state = state
      .iter()
      .map(|val| sigma(val, cs))
      .collect::<Result<Vec<_>, _>>()?;
    state = ark(t, (n_rounds_f / 2) * t, &state, &constants.c, cs)?;
    state = mix(t, &constants.p, cs, &state)?;

    // Partial rounds
    for r in 0..n_rounds_p {
      let sigma_result = sigma(&state[0], cs)?;
      let constant = AllocatedNum::alloc(cs.namespace(|| format!("partial_const_{}", r)), || {
        Ok(constants.c[(n_rounds_f / 2 + 1) * t + r])
      })?;
      let first = sigma_result.add(cs.namespace(|| format!("partial_add_{}", r)), &constant)?;
      state = mix_s(
        t,
        r,
        &constants.s,
        cs,
        &[vec![first], state[1..].to_vec()].concat(),
      )?;
    }

    // Return: [state0, state1, state2]
    println!("Circuit2 output state: [{:?}, {:?}, {:?}]", state[0], state[1], state[2]);
    
    Ok(state)
  }
}

fn main() {
  
}