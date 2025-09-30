use digest::consts::{U2, U3};
use nova_snark::frontend::{gadgets::poseidon::{HashType, SpongeTrait}, PoseidonConstants};
use ff::Field;
use halo2curves::bn256::Fr;
use nova_snark::{
    frontend::{
        gadgets::poseidon::{
            Elt, IOPattern, Simplex, Sponge, SpongeAPI, SpongeCircuit, SpongeOp, Strength,
        },
        num::AllocatedNum,
        ConstraintSystem, SynthesisError,
    },
    nova::{PublicParams, RecursiveSNARK},
    provider::{Bn256EngineKZG, GrumpkinEngine},
    traits::{circuit::StepCircuit, snark::RelaxedR1CSSNARKTrait, Engine, Group},
};

type E1 = Bn256EngineKZG;
type E2 = GrumpkinEngine;
type EE1 = nova_snark::provider::hyperkzg::EvaluationEngine<E1>;
type EE2 = nova_snark::provider::ipa_pc::EvaluationEngine<E2>;
type S1 = nova_snark::spartan::snark::RelaxedR1CSSNARK<E1, EE1>;
type S2 = nova_snark::spartan::snark::RelaxedR1CSSNARK<E2, EE2>;

#[derive(Clone, Debug)]
struct SimplePoseidonCircuit<G: Group> {
    a: G::Scalar,
    b: G::Scalar,
}

impl<G: Group> SimplePoseidonCircuit<G> {
    fn new(a: G::Scalar, b: G::Scalar) -> Self {
        Self { a, b }
    }
}

impl<G: Group> StepCircuit<G::Scalar> for SimplePoseidonCircuit<G> {
    fn arity(&self) -> usize {
        1 
    }

    fn synthesize<CS: ConstraintSystem<G::Scalar>>(
        &self,
        cs: &mut CS,
        _z_in: &[AllocatedNum<G::Scalar>],
    ) -> Result<Vec<AllocatedNum<G::Scalar>>, SynthesisError> {

        let a = AllocatedNum::alloc(cs.namespace(|| "input_a"), || Ok(self.a))?;
        let b = AllocatedNum::alloc(cs.namespace(|| "input_b"), || Ok(self.b))?;
 
        let inputs = vec![
            Elt::Allocated(a),
            Elt::Allocated(b),
        ];
        
        let pattern = IOPattern(vec![
            SpongeOp::Absorb(2),
            SpongeOp::Squeeze(1)   
        ]);
  
        let constants = PoseidonConstants::<G::Scalar, U2>::new_with_strength_and_type(Strength::Standard, HashType::ConstantLength(0));
        // print!("Constants: {:?}", constants);
    
        let mut ns = cs.namespace(|| "ns");

        let z_out = {
        let mut sponge = SpongeCircuit::new_with_constants(&constants, Duplex);
        let acc = &mut ns;

        sponge.start(pattern, None, acc);
        SpongeAPI::absorb(&mut sponge, 2, &inputs, acc);

        let output = SpongeAPI::squeeze(&mut sponge, 1, acc);
        sponge.finish(acc).unwrap();
        Elt::ensure_allocated(&output[0], &mut ns.namespace(|| "ensure allocated"), true)?
        };
        Ok(vec![z_out])
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🔐 === Simple Poseidon Hash [1, 2] ===");
    
    // Utwórz circuit z wartościami 1 i 2
    let circuit = SimplePoseidonCircuit::new(Fr::from(1), Fr::from(2));
    
    // Setup parametrów publicznych
    let pp = PublicParams::<E1, E2, SimplePoseidonCircuit<<E1 as Engine>::GE>>::setup(
        &circuit,
        &*S1::ck_floor(),
        &*S2::ck_floor(),
    )?;
    
    // Stan początkowy (pusty)
    let z0 = vec![<E1 as Engine>::Scalar::ZERO];
    
    // Utwórz i wykonaj dowód
    let mut recursive_snark = RecursiveSNARK::new(&pp, &circuit, &z0)?;
    recursive_snark.prove_step(&pp, &circuit)?;
    
    // Weryfikuj i pobierz wynik
    let result = recursive_snark.verify(&pp, 1, &z0)?[0];
    
    println!("Poseidon hash([1, 2]) = {:?}", result);
    println!("✅ Success!");
    
    Ok(())
}