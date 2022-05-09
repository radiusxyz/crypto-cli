use std::str;
mod arguments;
mod info_types;
use arguments::Args;
use clap::Parser;
use dusk_bytes::{DeserializableSlice, Serializable};
use dusk_plonk::prelude::*;
use encryptor::PoseidonEncryption;
use encryptor_zkp::PoseidonCircuit;
use info_types::{DecryptionInfo, EncryptionInfo};
use sapling_crypto::bellman::groth16;
use sapling_crypto::bellman::pairing::bn256::Bn256;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::thread;
use vdf::{ReturnData, VDF};
use vdf_zkp::VdfZKP;
use sapling_crypto::group_hash::BlakeHasher;
use sapling_crypto::poseidon::bn256::Bn256PoseidonParams;
use sapling_crypto::bellman::pairing::ff::PrimeField;
use sapling_crypto::poseidon::poseidon_hash;
use sapling_crypto::bellman::pairing::ff::to_hex;

fn main() {
  let args = Args::parse();
  let vdf: VDF = VDF::new(64, 10);
  let label = b"poseidon-cipher";

  if args.action_type == "encrypt" {
    let encryption_info: EncryptionInfo = serde_json::from_str(&args.data).unwrap();

    let message_bytes = encryption_info.plain_text.as_bytes();
    let message_length = message_bytes.len();
    let poseidon_encryption = PoseidonEncryption::new();

    let t = encryption_info.t.parse::<u64>().unwrap();
    let params = vdf.setup(t);
    let params: ReturnData = serde_json::from_str(params.as_str()).unwrap();

    let y_string = vdf.evaluate_with_trapdoor(t, params.g.clone(), params.n.clone(), params.remainder.clone());

    let y = y_string.as_bytes();
    let symmetric_key = PoseidonEncryption::calculate_secret_key(&y);

    let (cipher_text_hexes, nonce, message_scalar, cipher_scalar) = poseidon_encryption.encrypt(encryption_info.plain_text, symmetric_key);

    let mut vdf_proof_hex = "".to_string();
    
    let hash_params = Bn256PoseidonParams::new::<BlakeHasher>();
    let expected_commitment = PrimeField::from_str(y_string.as_str()).unwrap();
    let commitment = poseidon_hash::<Bn256>(&hash_params, &[expected_commitment])[0];
    let commitment_hex = to_hex(&commitment);
    
    if args.use_vdf_zkp == true {
      let mut vdf_zkp = VdfZKP::<Bn256>::new();
      vdf_zkp.import_parameter();

      let vdf_proof = vdf_zkp.generate_proof(hash_params,
        params.remainder.as_str(),
        params.p_minus_one.as_str(),
        params.q_minus_one.as_str(),
        params.quotient.as_str(),
        params.remainder.as_str(),
        params.g.as_str(),
        y_string.as_str(),
      );

      let mut vdf_proof_vector = vec![];
      vdf_proof.write(&mut vdf_proof_vector).unwrap();

      vdf_proof_hex = hex::encode(vdf_proof_vector.clone());
    }

    let mut encryption_proof_hex = "".to_string();
    if args.use_encryption_zkp == true {
      let mut poseidon_circuit = PoseidonCircuit::new();
      poseidon_circuit.import_parameter();

      let public_parameter = poseidon_circuit.public_parameter.clone().unwrap();
      let prover_key = poseidon_circuit.prover_key.clone().unwrap();
      let label = b"poseidon-cipher";

      poseidon_circuit.set_input(symmetric_key, nonce, &message_scalar[..], &cipher_scalar[..]);

      let proof = poseidon_circuit.prove(&public_parameter, &prover_key, label).unwrap();
      encryption_proof_hex = hex::encode(proof.to_bytes());
    }

    if args.use_vdf_zkp == true && args.use_encryption_zkp == true {
      println!(
        "{{
          \"message_length\": {}, 
          \"nonce\": \"{:?}\", 
          \"commitment\": {:?},
          \"g\": {:?}, 
          \"t\": {:?}, 
          \"two_two_t\": {:?},
          \"n\": {:?}, 
          \"cipher_text\": {:?}, 
          \"vdf_proof\": {:?},
          \"encryption_proof\": {:?}
        }}",
        message_length, nonce, commitment_hex, params.g, t, params.two_two_t, params.n, cipher_text_hexes, vdf_proof_hex, encryption_proof_hex
      );
    } else if args.use_vdf_zkp == true {
      println!(
        "{{
          \"message_length\": {}, 
          \"nonce\": \"{:?}\", 
          \"commitment\": {:?},
          \"g\": {:?}, 
          \"t\": {:?}, 
          \"two_two_t\": {:?},
          \"n\": {:?}, 
          \"cipher_text\": {:?}, 
          \"vdf_proof\": {:?}
        }}",
        message_length, nonce, commitment_hex, params.g, t, params.two_two_t, params.n, cipher_text_hexes, vdf_proof_hex
      );
    } else if args.use_encryption_zkp == true {
      println!(
        "{{
          \"message_length\": {}, 
          \"nonce\": \"{:?}\", 
          \"commitment\": {:?},
          \"g\": {:?}, 
          \"t\": {:?}, 
          \"two_two_t\": {:?},
          \"n\": {:?}, 
          \"cipher_text\": {:?}, 
          \"encryption_proof\": {:?}
        }}",
        message_length, nonce, commitment_hex, params.g, t, params.two_two_t, params.n, cipher_text_hexes, encryption_proof_hex
      );
    } else {
      println!(
        "{{
        \"message_length\": {}, 
        \"nonce\": \"{:?}\", 
        \"g\": {:?}, 
        \"t\": {:?}, 
        \"two_two_t\": {:?},
        \"n\": {:?}, 
        \"cipher_text\": {:?}
      }}",
        message_length, nonce, params.g, t, params.two_two_t, params.n, cipher_text_hexes
      );
    }
  } else if args.action_type == "decrypt" {
    let decryption_info: DecryptionInfo = serde_json::from_str(&args.data).unwrap();
    let poseidon_encryption = PoseidonEncryption::new();
    let t = decryption_info.t;
    let g = decryption_info.g.clone();
    let n = decryption_info.n.clone();
    let commitment = decryption_info.commitment.clone();

    if args.use_vdf_zkp == true {
      let mut vdf_zkp = VdfZKP::<Bn256>::new();
      vdf_zkp.import_parameter();

      let vdf_proof_vector = hex::decode(&decryption_info.vdf_proof).unwrap();
      let vdf_proof = groth16::Proof::<Bn256>::read(&vdf_proof_vector[..]).unwrap();

      let is_verified = vdf_zkp.verify(vdf_proof, commitment.as_str(), decryption_info.two_two_t.as_str(), decryption_info.g.as_str(), decryption_info.n.as_str());
      if is_verified == false {
        println!("VDF proof is invalid");
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
        println!("Encryption proof is invalid");
        return;
      }
    }

    let y = vdf.evaluate(t, g, n);
    let plain_text = decrypt(poseidon_encryption, y.as_bytes(), decryption_info);
    print!("{}", plain_text);
  } else if args.action_type == "batch_decrypt" {
    let file = File::open(args.batch_file_path).expect("Unable to read data");
    let reader = BufReader::new(file);
    let mut handles = Vec::new();

    let mut poseidon_circuit = PoseidonCircuit::new();
    poseidon_circuit.import_parameter();

    

    for line in reader.lines() {
      let data = line.expect("Unable to read line");
      let decryption_info: DecryptionInfo = serde_json::from_str(&data).unwrap();
      let poseidon_encryption = PoseidonEncryption::new();
      let t = decryption_info.t.clone();
      let g = decryption_info.g.clone();
      let n = decryption_info.n.clone();
      let commitment = decryption_info.commitment.clone();

      if args.use_thread == true {
        let vdf_proof = decryption_info.vdf_proof.clone();
        let two_two_t = decryption_info.two_two_t.clone();
        let encryption_proof = decryption_info.encryption_proof.clone();
        let cipher_text = decryption_info.cipher_text.clone();
        let public_parameter = poseidon_circuit.public_parameter.clone().unwrap();
        let verifier_data = poseidon_circuit.verifier_data.clone().unwrap();

        let handle = thread::spawn(move || {
          if args.use_vdf_zkp == true {
            let mut vdf_zkp = VdfZKP::<Bn256>::new();
            vdf_zkp.import_parameter();

            let vdf_proof_vector = hex::decode(&vdf_proof).unwrap();
            let vdf_proof = groth16::Proof::<Bn256>::read(&vdf_proof_vector[..]).unwrap();

            let is_verified = vdf_zkp.verify(vdf_proof, commitment.as_str(), two_two_t.as_str(), g.as_str(), n.as_str());

            if is_verified == false {
              println!("VDF proof is invalid");
              return;
            }
          }

          if args.use_encryption_zkp == true {
            let proof_bytes = hex::decode(&encryption_proof).unwrap();
            let proof = Proof::from_slice(&proof_bytes).unwrap();

            let mut public_input = vec![];
            for (_, cipher_text_hex) in cipher_text.iter().enumerate() {
              let chipher_text_hex_bytes = hex::decode(cipher_text_hex).unwrap().try_into().unwrap();
              let cipher_scalar = PoseidonEncryption::from_bytes(&chipher_text_hex_bytes).unwrap();
              cipher_scalar.iter().for_each(|c| {
                public_input.push(PublicInputValue::from(*c));
              });
            }

            let is_verified = PoseidonCircuit::verify(&public_parameter, &verifier_data, &proof, &public_input, label).is_ok();

            if is_verified == false {
              println!("Encryption proof is invalid");
              return;
            }
          }

          let y = &vdf.evaluate(t, g, n);
          let plain_text = decrypt(poseidon_encryption, y.as_bytes(), decryption_info);
          println!("{}", plain_text);
        });

        handles.push(handle);
      } else {
        let public_parameter = poseidon_circuit.public_parameter.clone().unwrap();
        let verifier_data = poseidon_circuit.verifier_data.clone().unwrap();
        
        if args.use_vdf_zkp == true {
          let mut vdf_zkp = VdfZKP::<Bn256>::new();
          vdf_zkp.import_parameter();

          let vdf_proof_vector = hex::decode(&decryption_info.vdf_proof).unwrap();
          let vdf_proof = groth16::Proof::<Bn256>::read(&vdf_proof_vector[..]).unwrap();

          let is_verified = vdf_zkp.verify(vdf_proof, commitment.as_str(), decryption_info.two_two_t.as_str(), decryption_info.g.as_str(), decryption_info.n.as_str());

          if is_verified == false {
            println!("VDF proof is invalid");
            return;
          }
        }

        if args.use_encryption_zkp == true {
          let proof_bytes = hex::decode(&decryption_info.encryption_proof).unwrap();
          let proof = Proof::from_slice(&proof_bytes).unwrap();

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
            println!("Encryption proof is invalid");
            return;
          }
        }

        let y = vdf.evaluate(t, g, n);
        let plain_text = decrypt(poseidon_encryption, y.as_bytes(), decryption_info);
        println!("{}", plain_text);
      }
    }

    for handle in handles {
      handle.join().unwrap();
    }
  }
}

fn decrypt(poseidon_encryption: PoseidonEncryption, y: &[u8], decryption_info: DecryptionInfo) -> String {
  // Generate symmetric key
  let symmetric_key = PoseidonEncryption::calculate_secret_key(&y);

  // Decrypt message with symmetric key
  let mut message = poseidon_encryption.decrypt(decryption_info.cipher_text, &symmetric_key, decryption_info.nonce);
  message.resize(decryption_info.message_length, 0);

  str::from_utf8(&message[..]).unwrap().to_string()
}
