use clap::Parser;

/// A command-line interface (CLI) to use Verifiable Delay Function (VDF) & Poseidon Encryption
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
pub struct Args {
  /// This is action type: (encrypt / decrypt / batch_decrypt)
  #[clap(long, default_value = "encrypt")]
  pub action_type: String,

  /// This is data which is needed for single encryption or decryption
  #[clap(long, default_value = "")]
  pub data: String,

  /// This
  #[clap(long, default_value = "")]
  pub batch_file_path: String,

  ///
  #[clap(long, parse(try_from_str), default_value = "true")]
  pub use_thread: bool,

  /// This is VDF algorithm type (radius / zengo)
  #[clap(long, default_value = "radius")]
  pub vdf_type: String,

  #[clap(long, parse(try_from_str), default_value = "true")]
  pub use_encryption_zkp: bool,

  #[clap(long, parse(try_from_str), default_value = "true")]
  pub use_vdf_zkp: bool,
}
