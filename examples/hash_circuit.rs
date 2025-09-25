use digest::consts::U1;
use digest::consts::U2;
use digest::consts::U3;
use digest::consts::U4;
use ff::Field;
use ff::PrimeField;
use halo2curves::bn256::Fr;
use nova_snark::{
  frontend::{
    gadgets::poseidon::{
      Elt, IOPattern, Simplex, Sponge, SpongeAPI, SpongeCircuit, SpongeOp, SpongeTrait, Strength,
    },
    num::AllocatedNum,
    ConstraintSystem, SynthesisError,
  },
  nova::{PublicParams, RecursiveSNARK},
  provider::{Bn256EngineKZG, GrumpkinEngine},
  traits::{circuit::StepCircuit, snark::RelaxedR1CSSNARKTrait, Engine, Group},
};
use std::hash::Hash;
use std::time::Instant;

type E1 = Bn256EngineKZG;
type E2 = GrumpkinEngine;
type EE1 = nova_snark::provider::hyperkzg::EvaluationEngine<E1>;
type EE2 = nova_snark::provider::ipa_pc::EvaluationEngine<E2>;
type S1 = nova_snark::spartan::snark::RelaxedR1CSSNARK<E1, EE1>;
type S2 = nova_snark::spartan::snark::RelaxedR1CSSNARK<E2, EE2>;

#[derive(Clone, Debug)]
struct PoseidonHashCircuit<G: Group> {
  data: Vec<G::Scalar>,
}

impl<G: Group> PoseidonHashCircuit<G> {
  fn new(data: Vec<G::Scalar>) -> Self {
    Self { data }
  }
}

impl<G: Group> StepCircuit<G::Scalar> for PoseidonHashCircuit<G> {
  /// Stan: [previous_hash] - hash z poprzedniego kroku
  fn arity(&self) -> usize {
    1 // tylko previous hash
  }

  /// Hashuje: [previous_hash, new_data] → new_hash
  fn synthesize<CS: ConstraintSystem<G::Scalar>>(
    &self,
    cs: &mut CS,
    z_in: &[AllocatedNum<G::Scalar>], // [previous_hash]
  ) -> Result<Vec<AllocatedNum<G::Scalar>>, SynthesisError> {
    // 1. Przygotuj dane do hashowania
    let previous_hash = &z_in[0];
    let new_data = AllocatedNum::alloc(cs.namespace(|| "data"), || Ok(self.data[0]))?;

    // 2. Input dla Poseidon: [previous_hash, new_data]
    let inputs = vec![previous_hash.clone(), new_data];
    let poseidon_inputs: Vec<Elt<G::Scalar>> =
      inputs.iter().map(|x| Elt::Allocated(x.clone())).collect();

    // 3. Konfiguracja Poseidon
    let pattern = IOPattern(vec![
      SpongeOp::Absorb(2),  // Wchłoń 2 elementy
      SpongeOp::Squeeze(1), // Wyciśnij 1 hash
    ]);
    let constants = Sponge::<G::Scalar, U3>::api_constants(Strength::Standard);

    // 4. Wykonaj hash w circuit (dodaje constraints)
    let mut sponge = SpongeCircuit::new_with_constants(&constants, Simplex);
    let mut ns = cs.namespace(|| "poseidon");

    sponge.start(pattern, None, &mut ns);
    SpongeAPI::absorb(&mut sponge, 2, &poseidon_inputs, &mut ns);
    let hash_result = SpongeAPI::squeeze(&mut sponge, 1, &mut ns);
    sponge.finish(&mut ns).unwrap();

    // 5. Zwróć nowy hash jako stan dla następnego kroku
    let new_hash = Elt::ensure_allocated(&hash_result[0], &mut ns, true)?;
    Ok(vec![new_hash])
  }
}

/// Przykład użycia Poseidon hash circuit
fn hash_example() -> Result<(), Box<dyn std::error::Error>> {
  println!("🔐 === POSEIDON HASH CIRCUIT ===");

  let numbers = vec![2];
  println!("Hashowanie: {:?}", numbers);

  // Template circuit
  let template_circuit = PoseidonHashCircuit::new(vec![Fr::from_u128(0)]);

  // Setup
  let pp = PublicParams::<E1, E2, PoseidonHashCircuit<<E1 as Engine>::GE>>::setup(
    &template_circuit,
    &*S1::ck_floor(),
    &*S2::ck_floor(),
  )?;

  // Stan początkowy: [initial_hash] - zaczynamy od 0
  let z0 = vec![<E1 as Engine>::Scalar::ZERO];

  let mut recursive_snark = RecursiveSNARK::new(&pp, &template_circuit, &z0)?;

  // Hash każdą liczbę po kolei
  for &number in numbers.iter() {
    let circuit = PoseidonHashCircuit::new(vec![Fr::from_u128(number)]);
    recursive_snark.prove_step(&pp, &circuit)?;
  }

  // Weryfikacja
  let final_hash = recursive_snark.verify(&pp, numbers.len(), &z0)?[0];

  println!("Final hash: {:?}", final_hash);
  println!("✅ Success!");

  Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
  // hash_example()?;
  simple_test()?;
  Ok(())
}

fn simple_test() -> Result<(), Box<dyn std::error::Error>> {
  println!("\n🔍 === SIMPLE HASH TEST ===");

  let data = vec![Fr::from_u128(1), Fr::from_u128(2)];
  let circuit = SimpleDirectHashCircuit::new(data);

  let pp = PublicParams::<E1, E2, SimpleDirectHashCircuit<<E1 as Engine>::GE>>::setup(
    &circuit,
    &*S1::ck_floor(),
    &*S2::ck_floor(),
  )?;

  let z0 = vec![Fr::from_u128(0)];
  let mut recursive_snark = RecursiveSNARK::new(&pp, &circuit, &z0)?;
  recursive_snark.prove_step(&pp, &circuit)?;

  let result = recursive_snark.verify(&pp, 1, &z0)?[0];

  println!("Nova hash([2]): {:?}", result);

  Ok(())
}

#[derive(Clone, Debug)]
struct SimpleDirectHashCircuit<G: Group> {
  value: G::Scalar,
}

impl<G: Group> SimpleDirectHashCircuit<G> {
  fn new(data: Vec<G::Scalar>) -> Self {
    Self { value: data[0] }
  }
}

impl<G: Group> StepCircuit<G::Scalar> for SimpleDirectHashCircuit<G> {
  fn arity(&self) -> usize {
    1
  }

  fn synthesize<CS: ConstraintSystem<G::Scalar>>(
    &self,
    cs: &mut CS,
    _z_in: &[AllocatedNum<G::Scalar>],
  ) -> Result<Vec<AllocatedNum<G::Scalar>>, SynthesisError> {
    let value = AllocatedNum::alloc(cs.namespace(|| "value"), || Ok(self.value))?;
    let input = vec![Elt::Allocated(value)];

    let pattern = IOPattern(vec![SpongeOp::Absorb(1), SpongeOp::Squeeze(1)]);
    let constants = Sponge::<G::Scalar, U2>::api_constants(Strength::Strengthened);
    println!("Constants: {:?}", constants);

    let mut sponge = SpongeCircuit::new_with_constants(&constants, Simplex);

    let mut ns = cs.namespace(|| "direct_hash");

    sponge.start(pattern, None, &mut ns);
    SpongeAPI::absorb(&mut sponge, 1, &input, &mut ns);
    let result = SpongeAPI::squeeze(&mut sponge, 1, &mut ns);
    sponge.finish(&mut ns).unwrap();

    let hash = Elt::ensure_allocated(&result[0], &mut ns, true)?;
    Ok(vec![hash])
  }
}
