use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct EncryptionInfo {
  #[serde(default)]
  pub plain_text: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct DecryptionInfo {
  #[serde(default)]
  pub message_length: usize,

  #[serde(default)]
  pub nonce: String,

  #[serde(default)]
  pub commitment: String,

  #[serde(default)]
  pub cipher_text: Vec<String>,

  #[serde(default)]
  pub vdf_snark_proof: String,

  #[serde(default)]
  pub r1: String,

  #[serde(default)]
  pub r3: String,

  #[serde(default)]
  pub s1: String,

  #[serde(default)]
  pub s3: String,

  #[serde(default)]
  pub k: String,

  #[serde(default)]
  pub encryption_proof: String,
}
