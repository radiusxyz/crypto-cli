use std::str::{self, FromStr};
mod arguments;
use num_bigint::BigUint;
mod info_types;
use arguments::Args;
use clap::Parser;
use dusk_bytes::{DeserializableSlice, Serializable};
use dusk_plonk::prelude::*;
use encryptor::PoseidonEncryption;
use encryptor_zkp::PoseidonCircuit;
use info_types::{DecryptionInfo, EncryptionInfo};
use sapling_crypto::bellman::pairing::bls12_381::Bls12;
use sapling_crypto::bellman::pairing::ff::from_hex;
use sapling_crypto::bellman::pairing::ff::to_hex;
use sapling_crypto::bellman::pairing::ff::ScalarEngine;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::thread;
use vdf_zkp::mimc;
use vdf_zkp::{nat_to_f, VdfProof, VdfZKP};
use vdf_zkp::group::{RsaGroup, SemiGroup};

macro_rules! init_big_uint_from_str {
  ($var:ident, $val:expr) => {
    let $var = BigUint::from_str($val).unwrap();
  };
}

fn get_symmetric_key(g: BigUint) -> String {
  let mut vdf_zkp = VdfZKP::<Bls12>::new();
  vdf_zkp.import_parameter();

  let vdf_params = vdf_zkp.clone().vdf_params.unwrap();
  let two = BigUint::from(2usize);
  let two_t = two.pow(vdf_params.t.into());
  init_big_uint_from_str!(n, vdf_params.n.as_str());
  
  g.modpow(&two_t, &n).to_string()
}

fn main() {
  let args = Args::parse();
  let label = b"poseidon-cipher";

  if args.action_type == "find_symmetric_key" {
    let decryption_info: DecryptionInfo = serde_json::from_str(&args.data).unwrap();
    let s1 = BigUint::from_str(decryption_info.s1.as_str()).unwrap();

    let symmetric_key = get_symmetric_key(s1);

    print!("{}", symmetric_key);
  } else if args.action_type == "verify" {
    let mut vdf_zkp = VdfZKP::<Bls12>::new();
    vdf_zkp.import_parameter();

    let decryption_info: DecryptionInfo = serde_json::from_str(&args.data).unwrap();
    let commitment_hex = decryption_info.commitment.clone();

    if args.use_vdf_zkp == true {
      let r1 = decryption_info.r1.as_str();
      let r3 = decryption_info.r3.as_str();
      let s1 = decryption_info.s1.as_str();
      let s3 = decryption_info.s3.as_str();
      let k = decryption_info.k.as_str();
      let vdf_proof_vector = hex::decode(&decryption_info.vdf_snark_proof).unwrap();
      let vdf_proof = VdfProof::new(r1, r3, s1, s3, k, vdf_proof_vector);
      let commitment = from_hex(commitment_hex.as_str()).unwrap();

      let is_verified = vdf_zkp.verify(commitment, vdf_proof);

      if is_verified == false {
        print!("false");
        return;
      }
    }

    if args.use_encryption_zkp == true {
      let proof_bytes = hex::decode(&decryption_info.encryption_proof).unwrap();
      let proof = Proof::from_slice(&proof_bytes).unwrap();

      let mut poseidon_circuit = PoseidonCircuit::new();
      poseidon_circuit.import_parameter();

      let public_parameter = poseidon_circuit.public_parameter.clone().unwrap();
      let verifier_data = poseidon_circuit.verifier_data.clone().unwrap();

      let mut public_input = vec![];

      for (_, cipher_text_hex) in decryption_info.cipher_text.iter().enumerate() {
        let chipher_text_hex_bytes = hex::decode(cipher_text_hex).unwrap().try_into().unwrap();
        let cipher_scalar = PoseidonEncryption::from_bytes(&chipher_text_hex_bytes).unwrap();
        cipher_scalar.iter().for_each(|c| {
          public_input.push(PublicInputValue::from(*c));
        });
      }

      let is_verified = PoseidonCircuit::verify(&public_parameter, &verifier_data, &proof, &public_input, label).is_ok();
      if is_verified == false {
        print!("false");
        return;
      }
    }

    print!("true");
  } else if args.action_type == "encrypt" {
    let mut vdf_zkp = VdfZKP::<Bls12>::new();
    vdf_zkp.import_parameter();
    let vdf_params = vdf_zkp.clone().vdf_params.unwrap();

    init_big_uint_from_str!(g_two_t, vdf_params.g_two_t.as_str());
    init_big_uint_from_str!(g, vdf_params.g.as_str());
    init_big_uint_from_str!(base, vdf_params.base.as_str());
    init_big_uint_from_str!(n, vdf_params.n.as_str());

    let encryption_info: EncryptionInfo = serde_json::from_str(&args.data).unwrap();

    let message_bytes = encryption_info.plain_text.as_bytes();
    let message_length = message_bytes.len();
    let poseidon_encryption = PoseidonEncryption::new();

    let s: u128 = fastrand::u128(..);
    let s = BigUint::from(s);
    let s2 = g_two_t.modpow(&s, &n);
    let s2_field = nat_to_f::<<Bls12 as ScalarEngine>::Fr>(&s2).unwrap();
    let commitment = mimc::helper::mimc(&[s2_field.clone(), s2_field.clone()]);
    let commitment_hex = to_hex(&commitment);

    let rsa_g = RsaGroup { n: n.clone(), g: base.clone() };
    let s1 = rsa_g.power(&g, &s);

    let symmetric_key = PoseidonEncryption::calculate_secret_key(s2.to_string().as_bytes());

    let (cipher_text_hexes, nonce, message_scalar, cipher_scalar) = poseidon_encryption.encrypt(encryption_info.plain_text, symmetric_key);

    let mut vdf_proof_hex = "".to_string();
    let mut r1 = "".to_string();
    let mut r3 = "".to_string();
    let s1 = s1.to_string();
    let mut s3 = "".to_string();
    let mut k = "".to_string();

    if args.use_vdf_zkp == true {
      let vdf_proof = vdf_zkp.generate_proof(commitment, s.to_string().as_str());

      r1 = vdf_proof.sigma_proof.r1.to_string();
      r3 = vdf_proof.sigma_proof.r3.to_string();
      s3 = vdf_proof.sigma_proof.s3.to_string();
      k = vdf_proof.sigma_proof.k.to_string();

      let mut vdf_proof_vector = vec![];
      vdf_proof.snark_proof.write(&mut vdf_proof_vector).unwrap();
      vdf_proof_hex = hex::encode(vdf_proof_vector.clone());
    }

    let mut encryption_proof_hex = "".to_string();
    if args.use_encryption_zkp == true {
      let mut poseidon_circuit = PoseidonCircuit::new();
      poseidon_circuit.import_parameter();

      let public_parameter = poseidon_circuit.public_parameter.clone().unwrap();
      let prover_key = poseidon_circuit.prover_key.clone().unwrap();

      let commitment = commitment_hex.as_bytes();
      let commitment: BlsScalar = BlsScalar::from_slice(commitment).unwrap();

      poseidon_circuit.set_input(symmetric_key, commitment, nonce, &message_scalar[..], &cipher_scalar[..]);

      let proof = poseidon_circuit.prove(&public_parameter, &prover_key, label).unwrap();
      encryption_proof_hex = hex::encode(proof.to_bytes());
    }

    if args.use_vdf_zkp == true && args.use_encryption_zkp == true {
      println!(
        "{{ \"message_length\": {}, \"nonce\": \"{:?}\", \"commitment\": {:?}, \"cipher_text\": {:?}, \"r1\": {:?}, \"r3\": {:?}, \"s1\": {:?}, \"s3\": {:?}, \"k\": {:?}, \"vdf_snark_proof\": {:?}, \"encryption_proof\": {:?} }}",
        message_length, nonce, commitment_hex, cipher_text_hexes, r1, r3, s1, s3, k, vdf_proof_hex, encryption_proof_hex,
      );
    } else if args.use_vdf_zkp == true {
      println!(
        "{{\"message_length\": {}, \"nonce\": \"{:?}\", \"commitment\": {:?}, \"cipher_text\": {:?}, \"r1\": {:?}, \"r3\": {:?}, \"s1\": {:?}, \"s3\": {:?}, \"k\": {:?}, \"vdf_snark_proof\": {:?} }}",
        message_length, nonce, commitment_hex, cipher_text_hexes, r1, r3, s1, s3, k, vdf_proof_hex
      );
    } else if args.use_encryption_zkp == true {
      println!(
        "{{\"message_length\": {}, \"nonce\": \"{:?}\", \"commitment\": {:?},\"cipher_text\": {:?}, \"s1\": {:?}, \"encryption_proof\": {:?}}}",
        message_length, nonce, commitment_hex, cipher_text_hexes, s1, encryption_proof_hex
      );
    } else {
      println!("{{\"message_length\": {}, \"nonce\": \"{:?}\", \"cipher_text\": {:?}, \"s1\": {:?}}}", message_length, nonce, cipher_text_hexes, s1);
    }
  } else if args.action_type == "decrypt" {
    let decryption_info: DecryptionInfo = serde_json::from_str(&args.data).unwrap();
    let poseidon_encryption = PoseidonEncryption::new();

    let s1 = BigUint::from_str(decryption_info.s1.as_str()).unwrap();
    let symmetric_key = get_symmetric_key(s1);

    let plain_text = decrypt(poseidon_encryption, symmetric_key, decryption_info);

    print!("{}", plain_text);
  } else if args.action_type == "batch_decrypt" {
    let file = File::open(args.batch_file_path).expect("Unable to read data");
    let reader = BufReader::new(file);
    let mut handles = Vec::new();

    for line in reader.lines() {
      let data = line.expect("Unable to read line");

      let decryption_info: DecryptionInfo = serde_json::from_str(&data).unwrap();
      let poseidon_encryption = PoseidonEncryption::new();

      let s1 = BigUint::from_str(decryption_info.s1.as_str()).unwrap();
      let symmetric_key = get_symmetric_key(s1);

      if args.use_thread == true {
        let handle = thread::spawn(move || {
          let plain_text = decrypt(poseidon_encryption, symmetric_key, decryption_info);
          println!("{}", plain_text);
        });

        handles.push(handle);
      } else {
        let plain_text = decrypt(poseidon_encryption, symmetric_key, decryption_info);
        println!("{}", plain_text);
      }
    }

    for handle in handles {
      handle.join().unwrap();
    }
  }
}

fn decrypt(poseidon_encryption: PoseidonEncryption, y: String, decryption_info: DecryptionInfo) -> String {
  // Generate symmetric key
  let symmetric_key = PoseidonEncryption::calculate_secret_key(&y.as_bytes());

  // Decrypt message with symmetric key
  let mut message = poseidon_encryption.decrypt(decryption_info.cipher_text, &symmetric_key, decryption_info.nonce);
  message.resize(decryption_info.message_length, 0);

  // Convert to String
  str::from_utf8(&message[..]).unwrap().to_string()
}
