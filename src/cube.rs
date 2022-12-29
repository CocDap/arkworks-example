
use ark_bls12_381::{Bls12_381, Fr};
use ark_r1cs_std::prelude::FieldVar;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError, Field}; 
use ark_r1cs_std::{fields::fp::FpVar, alloc::AllocVar};
use ark_r1cs_std::eq::EqGadget;
use ark_crypto_primitives::snark::*;

use crate::encode::encode_hex; // import Groth16 library

// proving that I know x such that x^3 + x + 5 == 35
// Generalized: x^3 + x + 5 == out
#[allow(clippy::upper_case_acronyms)]
#[derive(Clone)]
pub struct CubeDemo {
    pub x: Fr,
}

impl ConstraintSynthesizer<Fr> for CubeDemo { 
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {

        // x is the witness which should be hidden
        let x_witness = FpVar::<Fr>::new_witness(
            ark_relations::ns!(cs, "new witness x"), || Ok(self.x)
        ).expect("create new witness"); 

        let x_val = self.x;
        let tmp_square = x_val * x_val;
        let square_witness = FpVar::<Fr>::new_witness(
            ark_relations::ns!(cs, "new witness x^2"), || Ok(tmp_square)
        ).expect("create new witness");

        x_witness.square_equals(&square_witness)?;

       let tmp_cube = tmp_square * x_val;
       let cube_witness = FpVar::<Fr>::new_witness(
        ark_relations::ns!(cs, "new witness x^3"), || Ok(tmp_cube)
        ).expect("create new witness");

        square_witness.mul_equals(&x_witness, &cube_witness)?;

        let tmp_out = tmp_cube + x_val;
        let out = FpVar::<Fr>::new_input(
            ark_relations::ns!(cs, "new witness x^3 + x"), || Ok(tmp_out)
        ).expect("create new witness");

        out.enforce_equal(&(cube_witness + x_witness))?;

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
    use ark_std::rand::{rngs::StdRng, SeedableRng};
    use ark_groth16::*;
    use ark_ec::PairingEngine;
    use arkworks_native_gadgets::{to_field_elements, from_field_elements};
    use ark_serialize::*;
    use crate::encode;

    let mut rng = StdRng::seed_from_u64(0u64);

    let x = to_fq(3);

    let circuit = CubeDemo {
        x: x,
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

// #[test]
// fn test_cube_proof2(){
//     use ark_std::rand::{rngs::StdRng, SeedableRng};
//     use ark_groth16::*;
//     use ark_ec::PairingEngine;
//     use ark_serialize::*;
//     use arkworks_native_gadgets::{to_field_elements, from_field_elements};
//     use crate::encode;

//     let mut rng = StdRng::seed_from_u64(0u64);

//     let x = to_fq(3);

//     let circuit = CubeDemo {
//         x: x,
//     };

//     let mut statement = Vec::new();
//     statement.push(to_fq(30));
//     let enc_statement = [30];
//     let statement_hex = encode::encode_hex(&enc_statement);
//     println!("statement_hex{:?}", statement_hex);
//     println!("statement: {:?}", statement);

//     let param = generate_random_parameters::<Bls12_381, _, _>(circuit.clone(), &mut rng).unwrap();
//     let mut vkey_vec = Vec::new();
//     param.vk.serialize(&mut vkey_vec).unwrap();
//     println!("vkey_vec: {:?}", vkey_vec);

//     let proof = create_random_proof(circuit.clone(), &param, &mut rng).unwrap();
//     let mut proof_vec = Vec::new();
//     proof.serialize(&mut proof_vec).unwrap();
//     println!("proof_vec: {:?}", proof_vec);


//     let pvk = prepare_verifying_key(&param.vk);


//     // encode::encode_parameters(proof_vec, vkey_vec);

//     let result = verify_proof(&pvk, &proof, &statement).unwrap();
//     println!("verify result is {:?}", result);


//     let statement2: [u8; 1] = [0x1e];

//     let public_input = from_field_elements(&statement).unwrap();
//     let public_input_field_elts = to_field_elements(public_input.as_ref()).unwrap();
// 	let res = Groth16::verify(&param.vk, &public_input_field_elts, &proof);
//     println!("publicinputfie: {:?}", public_input_field_elts);
//     println!("pub_input: {:?}", public_input);
//     let hex_input = encode_hex(&public_input);
//     println!("hex_input: {:?}", hex_input);
//     println!("verify result is {:?}", res);

// }