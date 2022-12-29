use serde::{Deserialize, Serialize};

use std::fs::File;
use std::fs::OpenOptions;
use std::io::BufReader;
use std::io::Write;
use std::io;

use core::fmt::Write as encode_write;

#[derive(Serialize, Deserialize, Debug)]
struct Proof {
    pi_a: Vec<u8>,
    pi_b: Vec<u8>,
    pi_c: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug)]
struct VerifyKey {
    alpha_1: Vec<u8>,
    beta_1: Vec<u8>,
    beta_2: Vec<u8>,
    gamma_2: Vec<u8>,
    delta_1: Vec<u8>,
    delta_2: Vec<u8>,
    ic: Vec<Vec<u8>>,
}


pub fn encode_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        write!(&mut s, "{:02x}", b).unwrap();
    }
    s
}

pub fn encode_parameters(proof_serialized: Vec<u8>, vkey_serialized: Vec<u8>, public_input: Vec<u8>) -> Result<(), io::Error> {

    println!("... encoding serialized parameters");

    // let file = OpenOptions::new().read(true);
    
    let proof_hex = format!("{}{}", "0x", encode_hex(&proof_serialized));

    let vkey_hex = format!("{}{}", "0x", encode_hex(&vkey_serialized));

    let input_hex = format!("{}{}", "0x", encode_hex(&public_input));

    let mut file_proof = File::create("./file/proof.txt").unwrap();
    file_proof.write(proof_hex.as_bytes())?;

    let mut file_vkey = File::create("./file/vkey.txt").unwrap();
    file_vkey.write(vkey_hex.as_bytes())?;

    let mut file_input = File::create("./file/input.txt").unwrap();
    file_input.write(input_hex.as_bytes())?;


    Ok(())
}

pub fn encode_uncompressed_2inputs() -> Result<(), io::Error> {

    let proof_file = File::open("./file/proof_uncompressed.json").unwrap();
    let vkey_file = File::open("./file/vkey_uncompressed.json").unwrap();

    println!("... encoding uncompressed files");

    // let file = OpenOptions::new().read(true);

    let proof_reader = BufReader::new(proof_file);
    let vkey_reader = BufReader::new(vkey_file);

    let deserialized_proof: Proof = serde_json::from_reader(proof_reader).unwrap();
    let deserialized_vkey: VerifyKey = serde_json::from_reader(vkey_reader).unwrap();

    let pi_a = deserialized_proof.pi_a;
    let pi_b = deserialized_proof.pi_b;
    let pi_c = deserialized_proof.pi_c;
    
    let res_a = format!("{}{}", "0x", encode_hex(&pi_a));
    let res_b = format!("{}{}", "0x", encode_hex(&pi_b));
    let res_c = format!("{}{}", "0x", encode_hex(&pi_c));

    let vkey_a = deserialized_vkey.alpha_1;
    let vkey_b1 = deserialized_vkey.beta_1;
    let vkey_b2 = deserialized_vkey.beta_2;
    let vkey_g = deserialized_vkey.gamma_2;
    let vkey_d1 = deserialized_vkey.delta_1;
    let vkey_d2 = deserialized_vkey.delta_2;
    let vkey_ic_1 = &deserialized_vkey.ic[0];
    let vkey_ic_2 = &deserialized_vkey.ic[1];
    let vkey_ic_3 = &deserialized_vkey.ic[2];

    let res_va = format!("{}{}", "0x", encode_hex(&vkey_a));
    let res_vb1 = format!("{}{}", "0x", encode_hex(&vkey_b1));
    let res_vb2 = format!("{}{}", "0x", encode_hex(&vkey_b2));
    let res_vg = format!("{}{}", "0x", encode_hex(&vkey_g));
    let res_vd1 = format!("{}{}", "0x", encode_hex(&vkey_d1));
    let res_vd2 = format!("{}{}", "0x", encode_hex(&vkey_d2));
    let res_vic1 = format!("{}{}", "0x", encode_hex(&vkey_ic_1));
    let res_vic2 = format!("{}{}", "0x", encode_hex(&vkey_ic_2));
    let res_vic3 = format!("{}{}", "0x", encode_hex(&vkey_ic_3));

    let mut file_proofa = File::create("./file/proof_a.txt").unwrap();
    file_proofa.write(res_a.as_bytes())?;
    let mut file_proofb = File::create("./file/proof_b.txt").unwrap();
    file_proofb.write(res_b.as_bytes())?;
    let mut file_proofc = File::create("./file/proof_c.txt").unwrap();
    file_proofc.write(res_c.as_bytes())?;

    let mut file_vkey_a = File::create("./file/vkey_a.txt").unwrap();
    file_vkey_a.write(res_va.as_bytes())?;
    let mut file_vkey_b1 = File::create("./file/vkey_b1.txt").unwrap();
    file_vkey_b1.write(res_vb1.as_bytes())?;
    let mut file_vkey_b2 = File::create("./file/vkey_b2.txt").unwrap();
    file_vkey_b2.write(res_vb2.as_bytes())?;
    let mut file_vkey_g = File::create("./file/vkey_g.txt").unwrap();
    file_vkey_g.write(res_vg.as_bytes())?;
    let mut file_vkey_d1 = File::create("./file/vkey_d1.txt").unwrap();
    file_vkey_d1.write(res_vd1.as_bytes())?;
    let mut file_vkey_d2 = File::create("./file/vkey_d2.txt").unwrap();
    file_vkey_d2.write(res_vd2.as_bytes())?;
    let mut file_vkey_ic_1 = File::create("./file/vkey_ic_1.txt").unwrap();
    file_vkey_ic_1.write(res_vic1.as_bytes())?;
    let mut file_vkey_ic_2 = File::create("./file/vkey_ic_2.txt").unwrap();
    file_vkey_ic_2.write(res_vic2.as_bytes())?;
    let mut file_vkey_ic_3 = File::create("./file/vkey_ic_3.txt").unwrap();
    file_vkey_ic_3.write(res_vic3.as_bytes())?;

    Ok(())
}


pub fn encode_multi_uncompressed(count: u32, max_count: u32) -> Result<(), io::Error> {

    let proof_file = File::open(format!("{}{}{}", "./batch_file/proof", count, "_uncompressed.json")).unwrap();

    // let file = OpenOptions::new().read(true);

    let proof_reader = BufReader::new(proof_file);

    let deserialized_proof: Proof = serde_json::from_reader(proof_reader).unwrap();

    let pi_a = deserialized_proof.pi_a;
    let pi_b = deserialized_proof.pi_b;
    let pi_c = deserialized_proof.pi_c;
    
    let res_a = format!("{}{}", "0x", encode_hex(&pi_a));
    let res_b = format!("{}{}", "0x", encode_hex(&pi_b));
    let res_c = format!("{}{}", "0x", encode_hex(&pi_c));

    let mut file_proofa = File::create(format!("{}{}{}", "./batch_file/proof", count, "_a.txt")).unwrap();
    file_proofa.write(res_a.as_bytes())?;
    let mut file_proofb = File::create(format!("{}{}{}", "./batch_file/proof", count, "_b.txt")).unwrap();
    file_proofb.write(res_b.as_bytes())?;
    let mut file_proofc = File::create(format!("{}{}{}", "./batch_file/proof", count, "_c.txt")).unwrap();
    file_proofc.write(res_c.as_bytes())?;

    if count == max_count {
        let vkey_file = File::open(format!("{}{}{}", "./batch_file/vkey", count, "_uncompressed.json")).unwrap();
        let vkey_reader = BufReader::new(vkey_file);
        let deserialized_vkey: VerifyKey = serde_json::from_reader(vkey_reader).unwrap();

        let vkey_a = deserialized_vkey.alpha_1;
        let vkey_b1 = deserialized_vkey.beta_1;
        let vkey_b2 = deserialized_vkey.beta_2;
        let vkey_g = deserialized_vkey.gamma_2;
        let vkey_d1 = deserialized_vkey.delta_1;
        let vkey_d2 = deserialized_vkey.delta_2;
        let vkey_ic_1 = &deserialized_vkey.ic[0];
        let vkey_ic_2 = &deserialized_vkey.ic[1];
    
        let res_va = format!("{}{}", "0x", encode_hex(&vkey_a));
        let res_vb1 = format!("{}{}", "0x", encode_hex(&vkey_b1));
        let res_vb2 = format!("{}{}", "0x", encode_hex(&vkey_b2));
        let res_vg = format!("{}{}", "0x", encode_hex(&vkey_g));
        let res_vd1 = format!("{}{}", "0x", encode_hex(&vkey_d1));
        let res_vd2 = format!("{}{}", "0x", encode_hex(&vkey_d2));
        let res_vic1 = format!("{}{}", "0x", encode_hex(&vkey_ic_1));
        let res_vic2 = format!("{}{}", "0x", encode_hex(&vkey_ic_2));

        let mut file_vkey_a = File::create(format!("{}{}{}", "./batch_file/vkey", count, "_a.txt")).unwrap();
        file_vkey_a.write(res_va.as_bytes())?;
        let mut file_vkey_b1 = File::create(format!("{}{}{}", "./batch_file/vkey", count, "_b1.txt")).unwrap();
        file_vkey_b1.write(res_vb1.as_bytes())?;
        let mut file_vkey_b2 = File::create(format!("{}{}{}", "./batch_file/vkey", count, "_b2.txt")).unwrap();
        file_vkey_b2.write(res_vb2.as_bytes())?;
        let mut file_vkey_g = File::create(format!("{}{}{}", "./batch_file/vkey", count, "_g.txt")).unwrap();
        file_vkey_g.write(res_vg.as_bytes())?;
        let mut file_vkey_d1 = File::create(format!("{}{}{}", "./batch_file/vkey", count, "_d1.txt")).unwrap();
        file_vkey_d1.write(res_vd1.as_bytes())?;
        let mut file_vkey_d2 = File::create(format!("{}{}{}", "./batch_file/vkey", count, "_d2.txt")).unwrap();
        file_vkey_d2.write(res_vd2.as_bytes())?;
        let mut file_vkey_ic_1 = File::create(format!("{}{}{}", "./batch_file/vkey", count, "_ic_1.txt")).unwrap();
        file_vkey_ic_1.write(res_vic1.as_bytes())?;
        let mut file_vkey_ic_2 = File::create(format!("{}{}{}", "./batch_file/vkey", count, "_ic_2.txt")).unwrap();
        file_vkey_ic_2.write(res_vic2.as_bytes())?;
    }

    Ok(())

}
