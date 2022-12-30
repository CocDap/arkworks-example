
use ark_bls12_381::{Bls12_381, Fr};
use ark_ed_on_bls12_381::EdwardsAffine;
use ark_r1cs_std::prelude::*;
use ark_r1cs_std::uint8::UInt8;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError, Field}; 
use ark_r1cs_std::{fields::fp::FpVar, alloc::AllocVar};
use ark_r1cs_std::eq::EqGadget;
use ark_crypto_primitives::crh::injective_map::constraints::{
    PedersenCRHCompressorGadget, TECompressorGadget, 
};
use ark_crypto_primitives::crh::{ CRHGadget, CRH , pedersen::Parameters as PedersenParamsVar2 ,  pedersen::constraints::{CRHParametersVar as PedersenParamsVar}};
use ark_crypto_primitives::crh::{
    injective_map::{PedersenCRHCompressor, TECompressor},
    /*pedersen::constraints::CRHGadget,*/
    pedersen
};
use ark_ed_on_bls12_381::{constraints::EdwardsVar, EdwardsProjective as JubJub, EdwardsParameters, constraints::FqVar, EdwardsProjective};
use arkworks_native_gadgets::prelude::ark_ff::Fp256;

use crate::encode::encode_hex; // import Groth16 library

// pub type TwoToOneHash = PedersenCRHCompressor<JubJub, EdwardsVar, Window>;

#[derive(Clone, PartialEq, Eq, Hash)]
pub(super) struct Window;

// `WINDOW_SIZE * NUM_WINDOWS` = 2 * 256 bits = enough for hashing two outputs.
// impl pedersen::Window for TwoToOneWindow {
//     const WINDOW_SIZE: usize = 4;
//     const NUM_WINDOWS: usize = 128;
// }

impl pedersen::Window for Window {
    const WINDOW_SIZE: usize = 4;
    const NUM_WINDOWS: usize = 128;
}

// pub type PedeHash = PedersenCRHCompressor<JubJub, TECompressor, Window>;

pub type HashGadget = PedersenCRHCompressorGadget<
    JubJub,
    TECompressor,
    Window,
    EdwardsVar,
    TECompressorGadget,
>;
pub type ConstraintF = ark_ed_on_bls12_381::Fq;

/// The root of the account Merkle tree.
pub type Image = <TestCRHGadget as CRH>::Output;

pub type Image3 = ark_crypto_primitives::crh::pedersen::CRH<JubJub, Window>;

/// The R1CS equivalent of the the Merkle tree root.
// pub type ImageVar = <TestCRHGadget as CRHGadget<TestCRHGadget, ConstraintF>>::OutputVar;


// pub type HashParamsVar = <TwoToOneHashGadget as CRHGadget<TestCRHGadget, ConstraintF>>::ParametersVar;

type TestCRH = pedersen::CRH<JubJub, Window>;
type TestCRHGadget = pedersen::constraints::CRHGadget<JubJub, EdwardsVar, Window>;

// type Image2 = ark_crypto_primitives::crh::pedersen::CRH<JubJub, Window>::Output;
type ImageVar2 = <TestCRHGadget as CRHGadget<pedersen::CRH<EdwardsVar, Window>, ConstraintF>>::OutputVar;
// type ImageVar2 = <ark_crypto_primitives::crh::pedersen::constraints::CRHGadget<ark_ec::twisted_edwards_extended::GroupProjective<EdwardsParameters>, ark_r1cs_std::groups::curves::twisted_edwards::AffineVar<EdwardsParameters, FpVar<Fp256<ark_bls12_381::FrParameters>>>, Window> as CRHGadget<TestCRHGadget, ConstraintF>>::OutputVar;
type Image2 = <ark_crypto_primitives::crh::pedersen::CRH<ark_ec::twisted_edwards_extended::GroupProjective<EdwardsParameters>, Window> as CRH>::Output;

// type a = CRHGadget<JubJub, EdwardsVar, Window>;

pub type TwoToOneHash = PedersenCRHCompressor<EdwardsProjective, TECompressor, Window>;
type ImageVar4 = <HashGadget as CRHGadget<TwoToOneHash, ConstraintF>>::OutputVar;

// type Image5 = EdwardsVar<EdwardsParameters,>;

// proving that I know x such that x^3 + x + 5 == 35
// Generalized: x^3 + x + 5 == out
#[allow(clippy::upper_case_acronyms)]
#[derive(Clone)]
pub struct HashDemo {
    pub input: Vec<u8>,
    pub params: PedersenParamsVar2<JubJub>,
    pub image: Image2,
}

impl ConstraintSynthesizer<Fr> for HashDemo { 
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {

        let image = <EdwardsVar as AllocVar<EdwardsAffine, _>>::new_input(ark_relations::ns!(cs, "image_var"), || Ok(&self.image))?;
        // let two_to_one_crh_params =
        //     TwoToOneHashParamsVar::new_constant(cs.clone(), &self.params)?;

        let two_to_one_crh_params =
        pedersen::constraints::CRHParametersVar::new_constant(ark_relations::ns!(cs, "parameters"), &self.params)?;

        let mut input_bytes = vec![];
        for byte in self.input.iter() {
            input_bytes.push(UInt8::new_input(ark_relations::ns!(cs, "preimage"), || Ok(byte)).unwrap());
        }

        let hash_result_var = TestCRHGadget::evaluate(&two_to_one_crh_params, &input_bytes).unwrap();

        // let hash_result = hash_result_var.value().unwrap();
        // let hash_result = FpVar::<Fr>::new_witness(
        //     ark_relations::ns!(cs, "new witness x^2"), || Ok(hash_result_var.value())
        // ).expect("create new witness");
        // let image = image.value().unwrap();
        // image.enforce_equal(&hash_result_var.value().unwrap());
        hash_result_var.enforce_equal(&image)?;

        Ok(())
    }
}

// map i64 to a finite field Fp256
fn to_fq(x: i64) -> Fr {
    // get the positive value of x
    let val:u64 = i64::unsigned_abs(x); 
    // map integer to Fp256
    let mut fq: Fr = val.into();  
    if x< 0 { 
        // let modulus = ark_bls12_381::FrParameters::MODULUS;
        // println!("{:#?}", modu);
        // if x is negative, we should return the inverse value
        fq = - fq;   // neg_fq = modulus - fq
    }  
    fq
}



#[test]
fn test_cube_proof(){
    use ark_std::rand::{rngs::StdRng, SeedableRng, Rng};
    use ark_groth16::*;
    use ark_ec::PairingEngine;
    use arkworks_native_gadgets::{to_field_elements, from_field_elements};
    use ark_serialize::*;
    use crate::encode;

    let rng = &mut StdRng::seed_from_u64(0u64);

    let x = to_fq(3);

    let input = Vec::new();
    input.push(30);

    let parameters = TestCRH::setup(rng).unwrap();
    let primitive_result = TestCRH::evaluate(&parameters, input.as_slice()).unwrap();
    let circuit = HashDemo {
        input,
        params: parameters,
        image: primitive_result,
    };

    let mut statement = Vec::new();
    statement.push(to_fq(30));
    let public_input = from_field_elements(&statement).unwrap();
    println!("public_input: {:?}", public_input);

    let param = generate_random_parameters::<Bls12_381, _, _>(circuit.clone(), &mut rng).unwrap();
    let mut vkey_vec = Vec::new();
    param.vk.serialize(&mut vkey_vec).unwrap();
    println!("vkey_vec: {:?}", vkey_vec);

    let proof = create_random_proof(circuit.clone(), &param, &mut rng).unwrap();
    let mut proof_vec = Vec::new();
    proof.serialize(&mut proof_vec).unwrap();
    println!("proof_vec: {:?}", proof_vec);


    let pvk = prepare_verifying_key(&param.vk);


    encode::encode_parameters(proof_vec, vkey_vec, public_input);

    let result = verify_proof(&pvk, &proof, &statement).unwrap();
    println!("verify result is {:?}", result);

}
