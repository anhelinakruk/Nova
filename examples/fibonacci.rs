use ff::Field;
use ff::PrimeField;
use nova_snark::{
  frontend::{num::AllocatedNum, ConstraintSystem, SynthesisError},
  nova::{PublicParams, RecursiveSNARK},
  provider::{Bn256EngineKZG, GrumpkinEngine},
  traits::{circuit::StepCircuit, snark::RelaxedR1CSSNARKTrait, Engine},
};
use std::time::Instant;

type E1 = Bn256EngineKZG;
type E2 = GrumpkinEngine;
type EE1 = nova_snark::provider::hyperkzg::EvaluationEngine<E1>;
type EE2 = nova_snark::provider::ipa_pc::EvaluationEngine<E2>;
type S1 = nova_snark::spartan::snark::RelaxedR1CSSNARK<E1, EE1>;
type S2 = nova_snark::spartan::snark::RelaxedR1CSSNARK<E2, EE2>;

#[derive(Clone, Debug)]
struct FibonacciCircuit<F: Field> {
  _phantom: std::marker::PhantomData<F>,
}

impl<F: Field> FibonacciCircuit<F> {
  fn new() -> Self {
    Self {
      _phantom: std::marker::PhantomData,
    }
  }
}

impl<F: Field + ff::PrimeField> StepCircuit<F> for FibonacciCircuit<F> {
  /// 2 wartości w stanie: [poprzednia, obecna]
  fn arity(&self) -> usize {
    2
  }

  /// [a, b] → [b, a+b]
  fn synthesize<CS: ConstraintSystem<F>>(
    &self,
    cs: &mut CS,
    z: &[AllocatedNum<F>],
  ) -> Result<Vec<AllocatedNum<F>>, SynthesisError> {
    if z.len() != 2 {
      return Err(SynthesisError::Unsatisfiable);
    }

    let a = &z[0]; // Poprzednia liczba Fibonacci
    let b = &z[1]; // Obecna liczba Fibonacci

    let c = AllocatedNum::alloc(cs.namespace(|| "next fibonacci"), || {
      let a_val = a.get_value().unwrap_or(F::ZERO);
      let b_val = b.get_value().unwrap_or(F::ZERO);
      Ok(a_val + b_val)
    })?;

    // CONSTRAINT: Sprawdzamy że c = a + b
    // constraint weryfikuje że obliczenie jest poprawne
    cs.enforce(
      || "fibonacci constraint: c = a + b",
      |lc| lc + a.get_variable(),                    // a
      |lc| lc + CS::one(),                           // * 1
      |lc| lc + c.get_variable() - b.get_variable(), // = c - b
    );
    // Równanie: a * 1 = c - b  ⟺  a = c - b  ⟺  c = a + b

    // Zwracamy nowy stan: [b, c] (obecna staje się poprzednią, nowa staje się obecną)
    Ok(vec![b.clone(), c])
  }
}

/// 🧪 Test Fibonacci
fn fibonacci_example() -> Result<(), Box<dyn std::error::Error>> {
  println!("🔢 === FIBONACCI EXAMPLE ===");
  println!("Udowadniamy że potrafimy obliczyć sekwencję Fibonacci");
  println!();

  let circuit = FibonacciCircuit::new();

  // Setup - generujemy parametry publiczne
  println!("Generowanie parametrów publicznych");
  let start = Instant::now();
  let pp = PublicParams::<E1, E2, FibonacciCircuit<<E1 as Engine>::Scalar>>::setup(
    &circuit,
    &*S1::ck_floor(),
    &*S2::ck_floor(),
  )?;

  println!("Constraints per step: {}", pp.num_constraints().0);
  println!();

  let z0 = vec![
    u64_to_field::<<E1 as Engine>::Scalar>(1),
    u64_to_field::<<E1 as Engine>::Scalar>(1),
  ];

  println!("Generowanie proof dla 8 kroków");

  let mut recursive_snark = RecursiveSNARK::new(&pp, &circuit, &z0)?;

  let mut fib_a = 1u64;
  let mut fib_b = 1u64;

  println!("   Krok 0: F(0)={}, F(1)={}", fib_a, fib_b);

  // Wykonujemy 7 więcej kroków (łącznie 8)
  for step in 1..8 {
    let start = Instant::now();
    recursive_snark.prove_step(&pp, &circuit)?;

    let next = fib_a + fib_b;
    fib_a = fib_b;
    fib_b = next;

    println!(
      "   Krok {}: F({})={} (proving: {:?})",
      step,
      step + 1,
      fib_b,
      start.elapsed()
    );
  }

  // Weryfikacja
  println!();
  println!("Weryfikacja proof");
  let start = Instant::now();
  let final_state = recursive_snark.verify(&pp, 7, &z0)?;

  let final_a = field_to_u64(final_state[0]);
  let final_b = field_to_u64(final_state[1]);

  println!("Końcowy stan: [{}, {}]", final_a, final_b);
  println!("Oczekiwany 8 wyraz Fibonacci: 34");
  println!("Wynik: {}", if final_b == 34 { "OK" } else { "ERROR" });

  Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
  fibonacci_example()?;
  Ok(())
}

/// Konwertuje u64 na field element
fn u64_to_field<F: Field + PrimeField>(val: u64) -> F {
  F::from_u128(val as u128)
}

/// Konwertuje field element z powrotem na u64 (dla małych wartości)
fn field_to_u64<F: Field + PrimeField>(field: F) -> u64 {
  let bytes = field.to_repr();
  let mut result = 0u64;
  for (i, &byte) in bytes.as_ref().iter().take(8).enumerate() {
    result |= (byte as u64) << (i * 8);
  }
  result
}
