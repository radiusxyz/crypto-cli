use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct EncryptionInfo {
  #[serde(default)]
  pub plain_text: String,

  #[serde(default)]
  pub t: String,
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
  pub g: String,

  #[serde(default)]
  pub t: u64,

  #[serde(default)]
  pub two_two_t: String,

  #[serde(default)]
  pub n: String,

  #[serde(default)]
  pub cipher_text: Vec<String>,

  #[serde(default)]
  pub vdf_proof: String,

  #[serde(default)]
  pub encryption_proof: String,
}
