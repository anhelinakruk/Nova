use std::hash::Hash;

use digest::consts::{U1, U12, U14, U16, U2, U24, U3, U4, U5, U6, U7, U8};
use ff::{Field, PrimeField};
use halo2curves::bn256::Fr;
use nova_snark::frontend::{
  gadgets::poseidon::{round_constants, Poseidon, SpongeTrait},
  PoseidonConstants,
};
use nova_snark::{
  frontend::{
    gadgets::poseidon::{
      Elt, HashType, IOPattern, Matrix, Simplex, Sponge, SpongeAPI, SpongeCircuit, SpongeOp,
      Strength,
    },
    num::AllocatedNum,
    ConstraintSystem, SynthesisError,
  },
  nova::{PublicParams, RecursiveSNARK},
  provider::{Bn256EngineKZG, GrumpkinEngine},
  traits::{circuit::StepCircuit, snark::RelaxedR1CSSNARKTrait, Engine, Group},
};
use num_bigint::BigUint;

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
    1 // Output tylko hash
  }

  fn synthesize<CS: ConstraintSystem<G::Scalar>>(
    &self,
    cs: &mut CS,
    _z_in: &[AllocatedNum<G::Scalar>],
  ) -> Result<Vec<AllocatedNum<G::Scalar>>, SynthesisError> {
    // Alokuj wejścia [1, 2]
    let a = AllocatedNum::alloc(cs.namespace(|| "input_a"), || Ok(self.a))?;
    let b = AllocatedNum::alloc(cs.namespace(|| "input_b"), || Ok(self.b))?;

    // Przygotuj elementy dla Poseidon
    let inputs = vec![Elt::Allocated(a), Elt::Allocated(b)];

    // Konfiguracja Poseidon: absorb 2 elementy, squeeze 1 hash
    let pattern = IOPattern(vec![SpongeOp::Absorb(2), SpongeOp::Squeeze(1)]);

    // Helper function to convert Python hex to Scalar (moved to top)
    let hex_to_scalar = |hex_str: &str| -> G::Scalar {
      let clean = hex_str.trim_start_matches("0x");

      // Parse as big integer then convert to string for from_str_vartime
      let big_int = BigUint::parse_bytes(clean.as_bytes(), 16).expect("Invalid hex");

      // Convert to decimal string
      let decimal_str = big_int.to_string();

      // Parse as decimal (without 0x prefix)
      G::Scalar::from_str_vartime(&decimal_str)
        .unwrap_or_else(|| panic!("Failed to parse decimal: {}", decimal_str))
    };

    // let constants = Sponge::<G::Scalar, U8>::api_constants(Strength::Standard);
    // print!("Constants: {:?}", constants);

    let matr: Matrix<G::Scalar> = vec![
      vec![
        hex_to_scalar("0x109b7f411ba0e4c9b2b70caf5c36a7b194be7c11ad24378bfedb68592ba8118b"),
        hex_to_scalar("0x2969f27eed31a480b9c36c764379dbca2cc8fdd1415c3dded62940bcde0bd771"),
        hex_to_scalar("0x143021ec686a3f330d5f9e654638065ce6cd79e28c5b3753326244ee65a1b1a7"),
      ],
      vec![
        hex_to_scalar("0x16ed41e13bb9c0c66ae119424fddbcbc9314dc9fdbdeea55d6c64543dc4903e0"),
        hex_to_scalar("0x2e2419f9ec02ec394c9871c832963dc1b89d743c8c7b964029b2311687b1fe23"),
        hex_to_scalar("0x176cc029695ad02582a70eff08a6fd99d057e12e58e7d7b6b16cdfabc8ee2911"),
      ],
      vec![
        hex_to_scalar("0x2b90bba00fca0589f617e7dcbfe82e0df706ab640ceb247b791a93b74e36736d"),
        hex_to_scalar("0x101071f0032379b697315876690f053d148d4e109f5fb065c8aacc55a0f89bfa"),
        hex_to_scalar("0x19a3fc0a56702bf417ba7fee3802593fa644470307043f7773279cd71d25d5e0"),
      ],
    ];

    let python_hex_constants = [
      "0xee9a592ba9a9518d05986d656f40c2114c4993c11bb29938d21d47304cd8e6e",
      "0xf1445235f2148c5986587169fc1bcd887b08d4d00868df5696fff40956e864",
      "0x8dff3487e8ac99e1f29a058d0fa80b930c728730b7ab36ce879f3890ecf73f5",
      "0x84d520e4e5bb469e1f9075cb7c490efa59565eedae2d00ca8ef88ceea2b0197",
      "0x2d15d982d99577fa33da56722416fd734b3e667a2f9f15d8eb3e767ae0fd811e",
      "0xed2538844aba161cf1578a43cf0364e91601f6536a5996d0efbe65632c41b6d",
      "0x2600c27d879fbca186e739e6363c71cf804c877d829b735dcc3e3af02955e60a",
      "0x28f8bd44a583cbaa475bd15396430e7ccb99a5517440dfd970058558282bf2c5",
      "0x9cd7d4c380dc5488781aad012e7eaef1ed314d7f697a5572d030c55df153221",
      "0x11bb6ee1291aabb206120ecaace460d24b6713febe82234951e2bee7d0f855f5",
      "0x2d74e8fa0637d9853310f3c0e3fae1d06f171580f5b8fd05349cadeecfceb230",
      "0x2735e4ec9d39bdffac9bef31bacba338b1a09559a511a18be4b4d316ed889033",
      "0xf03c1e9e0895db1a5da6312faa78e971106c33f826e08dcf617e24213132dfd",
      "0x17094cd297bf827caf92920205b719c18741090b8f777811848a7e9ead6778c4",
      "0xdb8f419c21f92461fc2b3219465798348df90d4178042c81ba7d4b4d559e2b8",
      "0x243443613f64ffa417427ed5933fcfbc66809db60b9ca1724a22709ceceeece2",
      "0x22af49fbfd5d7e9fcd256c25c07d3dd8ecbbae6deecd03aa04bb191fada75411",
      "0x14fbd37fa8ad6e4e0c78a20d93c7230c4677f797b4327323f7f7c097c19420e0",
      "0x15a9298bbb882534d4b2c9fbc6e4ef4189420c4eb3f3e1ea22faa7e18b5ae625",
      "0x2f7de75f23ddaaa5221323ebceb2f2ac83eef92e854e75434c2f1d90562232bc",
      "0x36a4432a868283b78a315e84c4ae5aeca216f2ff9e9b2e623584f7479cd5c27",
      "0x2180d7786a8cf810e277218ab14a11e5e39f3c962f11e860ae1c5682c797de5c",
      "0xa268ef870736eebd0cb55be640d73ee3778990484cc03ce53572377eefff8e4",
      "0x1eefefe11c0be4664f2999031f15994829e982e8c90e09069df9bae16809a5b2",
      "0x27e87f033bd1e0a89ca596e8cb77fe3a4b8fb93d9a1129946571a3c3cf244c52",
      "0x1498a3e6599fe243321f57d6c5435889979c4f9d2a3e184d21451809178ee39",
      "0x27c0a41f4cb9fe67e9dd4d7ce33707f74d5d6bcc235bef108dea1bbebde507aa",
      "0x1f75230908b141b46637238b120fc770f4f4ae825d5004c16a7c91fe1dae280f",
      "0x25f99a9198e923167bba831b15fffd2d7b97b3a089808d4eb1f0a085bee21656",
      "0x101bc318e9ea5920d0f6acdc2bb526593d3d56ec8ed14c67622974228ba900c6",
      "0x1a175607067d517397c1334ecb019754ebc0c852a3cf091ec1ccc43207a83c76",
      "0xf02f0e6d25f9ea3deb245f3e8c381ee6b2eb380ba4af5c1c4d89770155df37b",
      "0x151d757acc8237af08d8a6677203ec9692565de456ae789ff358b3163b393bc9",
      "0x256cd9577cea143049e0a1fe0068dd20084980ee5b757890a79d13a3a624fad4",
      "0x513abaff6195ea48833b13da50e0884476682c3fbdd195497b8ae86e1937c61",
      "0x1d9570dc70a205f36f610251ee6e2e8039246e84e4ac448386d19dbac4e4a655",
      "0x18f1a5194755b8c5d5d7f1bf8aaa6f56effb012dd784cf5e044eec50b29fc9d4",
      "0x266b53b615ef73ac866512c091e4a4f2fa4bb0af966ef420d88163238eebbca8",
      "0x2d63234c9207438aa42b8de27644c02268304dfeb8c89a1a3f4fd6e8344ae0f7",
      "0x2ab30fbe51ee49bc7b3adde219a6f0b5fbb976205ef8df7e0021daee6f55c693",
      "0x1aee6d4b3ebe9366dcb9cce48969d4df1dc42abcd528b270068d9207fa6a45c9",
      "0x1891aeab71e34b895a79452e5864ae1d11f57646c60bb34aa211d123f6095219",
      "0x24492b5f95c0b0876437e94b4101c69118e16b2657771bd3a7caab01c818aa4b",
      "0x1752161b3350f7e1b3b2c8663a0d642964628213d66c10ab2fddf71bcfde68f",
      "0xab676935722e2f67cfb84938e614c6c2f445b8d148de54368cfb8f90a00f3a7",
      "0xb0f72472b9a2f5f45bc730117ed9ae5683fc2e6e227e3d4fe0da1f7aa348189",
      "0x16aa6f9273acd5631c201d1a52fc4f8acaf2b2152c3ae6df13a78a513edcd369",
      "0x2f60b987e63614eb13c324c1d8716eb0bf62d9b155d23281a45c08d52435cd60",
      "0x18d24ae01dde92fd7606bb7884554e9df1cb89b042f508fd9db76b7cc1b21212",
      "0x4fc3bf76fe31e2f8d776373130df79d18c3185fdf1593960715d4724cffa586",
      "0xd18f6b53fc69546cfdd670b41732bdf6dee9e06b21260c6b5d26270468dbf82",
      "0xba4231a918f13acec11fbafa17c5223f1f70b4cdb045036fa5d7045bd10e24",
      "0x7b458b2e00cd7c6100985301663e7ec33c826da0635ff1ebedd0dd86120b4c8",
      "0x1c35c2d96db90f4f6058e76f15a0c8286bba24e2ed40b16cec39e9fd7baa5799",
      "0x1d12bea3d8c32a5d766568f03dd1ecdb0a4f589abbef96945e0dde688e292050",
      "0xd953e20022003270525f9a73526e9889c995bb62fdea94313db405a61300286",
      "0x29f053ec388795d786a40bec4c875047f06ff0b610b4040a760e33506d2671e1",
      "0x4188e33735f46b14a4952a98463bc12e264d5f446e0c3f64b9679caaae44fc2",
      "0x149ec28846d4f438a84f1d0529431bb9e996a408b7e97eb3bf1735cdbe96f68f",
      "0xde20fae0af5188bca24b5f63630bad47aeafd98e651922d148cce1c5fdddee8",
      "0x12d650e8f790b1253ea94350e722ad2f7d836c234b8660edf449fba6984c6709",
      "0x22ab53aa39f34ad30ea96717ba7446aafdadbc1a8abe28d78340dfc4babb8f6c",
      "0x26503e8d4849bdf5450dabea7907bc3de0de109871dd776904a129db9149166c",
      "0x1d5e7a0e2965dffa00f5454f5003c5c8ec34b23d897e7fc4c8064035b0d33850",
      "0xee3d8daa098bee012d96b7ec48448c6bc9a6aefa544615b9cb3c7bbd07104cb",
      "0x1bf282082a04979955d30754cd4d9056fa9ef7a7175703d91dc232b5f98ead00",
      "0x7ae1344abfc6c2ce3e951bc316bee49971645f16b693733a0272173ee9ad461",
      "0x217e3a247827c376ec21b131d511d7dbdc98a36b7a47d97a5c8e89762ee80488",
      "0x215ffe584b0eb067a003d438e2fbe28babe1e50efc2894117509b616addc30ee",
      "0x1e770fc8ecbfdc8692dcedc597c4ca0fbec19b84e33da57412a92d1d3ce3ec20",
      "0x2f6243cda919bf4c9f1e3a8a6d66a05742914fc19338b3c0e50e828f69ff6d1f",
      "0x246efddc3117ecd39595d0046f44ab303a195d0e9cc89345d3c03ff87a11b693",
      "0x53e8d9b3ea5b8ed4fe006f139cbc4e0168b1c89a918dfbe602bc62cec6adf1",
      "0x1b894a2f45cb96647d910f6a710d38b7eb4f261beefff135aec04c1abe59427b",
      "0xaeb1554e266693d8212652479107d5fdc077abf88651f5a42553d54ec242cc0",
      "0x16a735f6f7209d24e6888680d1781c7f04ba7d71bd4b7d0e11faf9da8d9ca28e",
      "0x487b8b7fab5fc8fd7c13b4df0543cd260e4bcbb615b19374ff549dcf073d41b",
      "0x1e75b9d2c2006307124bea26b0772493cfb5d512068c3ad677fdf51c92388793",
      "0x5120e3d0e28003c253b46d5ff77d272ae46fa1e239d1c6c961dcb02da3b388f",
      "0xda5feb534576492b822e8763240119ac0900a053b171823f890f5fd55d78372",
      "0x2e211b39a023031a22acc1a1f5f3bb6d8c2666a6379d9d2c40cc8f78b7bd9abe",
    ];

    let arity = 2;
    let strength = Strength::Standard;
    let round_constants = round_constants(arity, &strength);

    println!("Round constants generated: {}", round_constants.len());

    // let conts = PoseidonConstants::<G::Scalar, U2>::new_with_strength(Strength::Standard);
    let conts = PoseidonConstants::<G::Scalar, U2>::new_from_parameters(
      3,
      matr,
      round_constants,
      8,
      57,
      HashType::Sponge,
      Strength::Standard,
    );
    let mut hasher = Poseidon::<G::Scalar, U2>::new(&conts);

    let result_scalar = hasher.hash_optimized_static();

    println!("Hash result with optimized_static: {:?}", result_scalar);

    let hash = AllocatedNum::alloc(cs.namespace(|| "poseidon_result"), || Ok(result_scalar))?;
    Ok(vec![hash])
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
