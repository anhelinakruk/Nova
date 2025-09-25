use ff::{Field, PrimeField};
use nova_snark::{frontend::{num::AllocatedNum, ConstraintSystem, SynthesisError}, traits::circuit::StepCircuit};

#[derive(Clone)]
struct PoseidonCircuit<F: Field> {
    _state: std::marker::PhantomData<Vec<F>>,
}

impl<F: Field> PoseidonCircuit<F> {
    fn new() -> Self {
        Self {
            _state: std::marker::PhantomData,
        }
    }
}

fn ark<F: Field + PrimeField>(
    t: usize,
    r: usize,
    state: &[AllocatedNum<F>],
    poseidon_c: Vec<F>,
    mut cs: impl ConstraintSystem<F>,
) -> Result<Vec<AllocatedNum<F>>, SynthesisError> {
    let mut ark_output = Vec::new();

    for i in 0..t {
        let constant = AllocatedNum::alloc(
            cs.namespace(|| format!("ark_constant_{}", i)),
            || Ok(poseidon_c[i + r]),
        )?;

        let sum = state[i].add(cs.namespace(|| format!("ark_add_{}", i)), &constant)?;
        ark_output.push(sum.clone());
        print!("ark_output[{}]: {:?}\n", i, sum.clone().get_value());
    }

    Ok(ark_output)
}

fn sigma<F: Field + PrimeField>(
    value: &AllocatedNum<F>,
    cs: &mut impl ConstraintSystem<F>,
) -> Result<AllocatedNum<F> , SynthesisError> {
    let x = value;

    let x2 = x.mul(cs.namespace(|| "x^2"), x).unwrap();
    let x4 = x2.mul(cs.namespace(|| "x^4"), &x2).unwrap();
    let x5 = x4.mul(cs.namespace(|| "x^5"), x).unwrap();

    Ok(x5)
}

fn iterated_add<F: Field + PrimeField>(
    cs: &mut impl ConstraintSystem<F>,
    terms: &[AllocatedNum<F>],
) -> Result<AllocatedNum<F>, SynthesisError> {
    let mut sum = terms[0].clone();

    for term in &terms[1..] {
        sum = sum.add(cs.namespace(|| "iterated_add"), term)?;
    }

    Ok(sum)
}

fn mix<F: Field + PrimeField>(
    t: usize,
    poseidon_m: Vec<Vec<F>>,
    cs: &mut impl ConstraintSystem<F>,
    state: &[AllocatedNum<F>],
) -> Result<Vec<AllocatedNum<F>>, SynthesisError> {
    let mut new_state = Vec::new();

    for i in 0..t {
        let mut terms = Vec::new();
        for j in 0..t {
            let constant = AllocatedNum::alloc(
                cs.namespace(|| format!("mix_constant_{}_{}", i, j)),
                || Ok(poseidon_m[i][j]),
            )?;
            let term = state[j].mul(
                cs.namespace(|| format!("mix_mul_{}_{}", i, j)), &constant,
            )?;
            terms.push(term);
        }
        let mixed = iterated_add(&mut cs.namespace(|| format!("mix_add_{}", i)), &terms)?;
        new_state.push(mixed);
    }

    Ok(new_state)
}

fn main() {}

// impl<F: Field + PrimeField> StepCircuit<F> for PoseidonCircuit<F> {
//     fn arity(&self) -> usize {
//         3 
//     }

//     fn synthesize<CS: ConstraintSystem<F>>(
//         &self,
//         cs: &mut CS,
//         z: &[AllocatedNum<F>],
//     ) -> Result<Vec<AllocatedNum<F>>, SynthesisError> {
//         let t = 3;
//         let r = 0;
        
//         let poseidon_c = vec![
//             Fr::from_str_vartime("6745197990210204598374042828761989596302876299545964402857411729872131034734").unwrap(),  // 0xee9a592ba9a9518d05986d656f40c2114c4993c11bb29938d21d47304cd8e6e
//             Fr::from_str_vartime("426281677759936592021316809065178817848084678679510574715894138690250139748").unwrap(),   // 0xf1445235f2148c5986587169fc1bcd887b08d4d00868df5696fff40956e864
//             Fr::from_str_vartime("4014188762916583598888942667424965430287497824629657219807941460227372577781").unwrap(), // 0x8dff3487e8ac99e1f29a058d0fa80b930c728730b7ab36ce879f3890ecf73f5
//         ];

//         println!("Poseidon constants: {:?}", poseidon_c);

//         let mut  state = Vec::new();

//         for i in 0..t {
//             let constant = AllocatedNum::alloc(
//                 cs.namespace(|| format!("poseidon_constant_{}", i)),
//                 || Ok(poseidon_c[i + r]),
//             )?;
            
//             let sum = z[i].add(cs.namespace(|| format!("poseidon_add_{}", i)), &constant)?;
//             state.push(sum.clone());
//             print!("State[{}]: {:?}\n", i, sum.clone().get_value());
//         }


//         Ok(state)
//     }
// }

// fn main() {
//     let circuit = PoseidonCircuit::<Fr>::new();
//     let z0 = vec![
//         Fr::from(0u64),
//         Fr::from(1u64),
//         Fr::from(2u64),
//     ];
// }