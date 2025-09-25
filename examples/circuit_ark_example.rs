use ff::{Field, PrimeField};
use halo2curves::bn256::Fr;
use nova_snark::{frontend::{num::AllocatedNum, ConstraintSystem, SynthesisError}, nova::{PublicParams, RecursiveSNARK}, provider::{Bn256EngineKZG, GrumpkinEngine}, traits::{circuit::StepCircuit, snark::RelaxedR1CSSNARKTrait}};

type E1 = Bn256EngineKZG;
type E2 = GrumpkinEngine;
type EE1 = nova_snark::provider::hyperkzg::EvaluationEngine<E1>;
type EE2 = nova_snark::provider::ipa_pc::EvaluationEngine<E2>;
type S1 = nova_snark::spartan::snark::RelaxedR1CSSNARK<E1, EE1>;
type S2 = nova_snark::spartan::snark::RelaxedR1CSSNARK<E2, EE2>;

#[derive(Clone)]
struct ArkCircuit<F: Field> {
    _state: std::marker::PhantomData<Vec<F>>,
}

impl<F: Field> ArkCircuit<F> {
    fn new() -> Self {
        Self {
            _state: std::marker::PhantomData,
        }
    }
}

impl<F: Field + PrimeField> StepCircuit<F> for ArkCircuit<F> {
    fn arity(&self) -> usize {
        3 
    }

    fn synthesize<CS: ConstraintSystem<F>>(
        &self,
        cs: &mut CS,
        z: &[AllocatedNum<F>],
    ) -> Result<Vec<AllocatedNum<F>>, SynthesisError> {
        let t = 3;
        let r = 0;
        
        let poseidon_c = vec![
            F::from_str_vartime("6745197990210204598374042828761989596302876299545964402857411729872131034734").unwrap(),  // 0xee9a592ba9a9518d05986d656f40c2114c4993c11bb29938d21d47304cd8e6e
            F::from_str_vartime("426281677759936592021316809065178817848084678679510574715894138690250139748").unwrap(),   // 0xf1445235f2148c5986587169fc1bcd887b08d4d00868df5696fff40956e864
            F::from_str_vartime("4014188762916583598888942667424965430287497824629657219807941460227372577781").unwrap(), // 0x8dff3487e8ac99e1f29a058d0fa80b930c728730b7ab36ce879f3890ecf73f5
        ];

        println!("Poseidon constants: {:?}", poseidon_c);

        let mut ark_output = Vec::new();

        for i in 0..t {
            let constant = AllocatedNum::alloc(
                cs.namespace(|| format!("ark_constant_{}", i)),
                || Ok(poseidon_c[i + r]),
            )?;
            
            let sum = z[i].add(cs.namespace(|| format!("ark_add_{}", i)), &constant)?;
            ark_output.push(sum.clone());
            print!("ark_output[{}]: {:?}\n", i, sum.clone().get_value());
        }

        Ok(ark_output)
    }
}

fn main() {
    let circuit = ArkCircuit::<Fr>::new();
    let z0 = vec![
        Fr::from(0u64),
        Fr::from(1u64),
        Fr::from(2u64),
    ];

    let pp = PublicParams::<E1, E2, ArkCircuit<Fr>>::setup(
        &circuit,
        &*S1::ck_floor(),
        &*S2::ck_floor(),
    ).unwrap();

    let mut snark = RecursiveSNARK::new(
        &pp,
        &circuit,
        &z0,
    ).unwrap();

    snark.prove_step(&pp, &circuit).unwrap();
    let result = snark.verify(&pp, 1, &z0).unwrap();
    println!("Circuit verification result: {:?}", result);
}