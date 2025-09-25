use std::marker::PhantomData;

use ff::{Field, PrimeField};
use halo2curves::bn256::Fr;
use nova_snark::provider::Bn256EngineKZG;
use nova_snark::provider::GrumpkinEngine;
use nova_snark::traits::snark::RelaxedR1CSSNARKTrait;
use nova_snark::{frontend::{num::AllocatedNum, ConstraintSystem, SynthesisError}, nova::{PublicParams, RecursiveSNARK}, traits::circuit::StepCircuit};

type E1 = Bn256EngineKZG;
type E2 = GrumpkinEngine;
type EE1 = nova_snark::provider::hyperkzg::EvaluationEngine<E1>;
type EE2 = nova_snark::provider::ipa_pc::EvaluationEngine<E2>;
type S1 = nova_snark::spartan::snark::RelaxedR1CSSNARK<E1, EE1>;
type S2 = nova_snark::spartan::snark::RelaxedR1CSSNARK<E2, EE2>;

#[derive(Clone)]
struct SigmaCircuit<F: Field> {
    _value: PhantomData<F>,
}

impl<F: Field> SigmaCircuit<F> {
    fn new() -> Self {
        Self { _value: PhantomData }
    }
}

impl<F: Field + PrimeField> StepCircuit<F> for SigmaCircuit<F> {
    fn arity(&self) -> usize {
        1
    }

    fn synthesize<CS: ConstraintSystem<F>>(
        &self,
        cs: &mut CS,
        z: &[AllocatedNum<F>],
      ) -> Result<Vec<AllocatedNum<F>>, SynthesisError> {
        let x = &z[0];

        let x2 = x.mul(cs.namespace(|| "x^2"), x).unwrap();
        let x4 = x2.mul(cs.namespace(|| "x^4"), &x2).unwrap();
        let x5 = x4.mul(cs.namespace(|| "x^5"), x).unwrap();

        Ok(vec![x5])
    }
}

fn main() {
    let circuit: SigmaCircuit<Fr> = SigmaCircuit::new();

    let pp = PublicParams::<E1, E2, SigmaCircuit<Fr>>::setup(
        &circuit,
        &*S1::ck_floor(),
        &*S2::ck_floor(),
    ).unwrap();

    let z0 = vec![Fr::from_u128(2)];

    let mut recursive_snark = RecursiveSNARK::new(&pp, &circuit, &z0).unwrap();
    recursive_snark.prove_step(&pp, &circuit).unwrap();
    let result = recursive_snark.verify(&pp, 1, &z0).unwrap()[0];
    println!("Result: {:?}", result); 
}