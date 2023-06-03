// -- imports --
use crate::core::*;
use clap::Parser;
use std::error::Error;

// -- clap options --
/// Mirai's experimental, quantum-safe successor to GPG
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None, arg_required_else_help = true)]
pub struct Args {
    /// Generates a new KDT owned key set and stores it in the
    /// local owned key database
    #[arg(short, long)]
    pub gen_key: bool,

    /// Imports a KDT public key from stdin and stores it in the
    /// local public key database
    #[arg(short, long)]
    pub import: bool,

    /// Launches KDT in decryption mode
    #[arg(short, long, value_name = "PRIVATE_KEY_ID")]
    pub decrypt: Option<String>,

    /// Launches KDT in encryption mode
    #[arg(short, long, value_name = "PUBLIC_KEY_ID")]
    pub encrypt: Option<String>,

    /// Lists all keys in the public key database
    #[arg(long)]
    pub list_keys: bool,

    /// Lists all keys in the owned key database
    #[arg(short, long)]
    pub list_key_pairs: bool,

    /// Exports the public key in the owned key set containing
    /// a private key of id `PRIVATE_KEY_ID`
    #[arg(long, value_name = "PRIVATE_KEY_ID")]
    pub export_pubkey: Option<String>,

    /// Removes the public key with id `PUBLIC_KEY_ID`
    /// from the public key database
    #[arg(long, value_name = "PUBLIC_KEY_ID")]
    pub del_pubkey: Option<String>,

    /// Removes the owned key set with private key of
    /// id `PRIVATE_KEY_ID` from the owned key database
    #[arg(long, value_name = "PRIVATE_KEY_ID")]
    pub del_keyset: Option<String>,

    /// Signs a message with the given private key
    #[arg(short, long, value_name = "PRIVATE_KEY_ID")]
    pub sign: Option<String>,

    /// Verifies the integrity of the given signed message
    /// against the given public key
    #[arg(short, long, value_name = "PUBLIC_KEY_ID")]
    pub verify: Option<String>,
}

impl Args {
    pub fn get_num_called(&self) -> usize {
        [
            self.gen_key,
            self.import,
            self.list_keys,
            self.list_key_pairs,
            self.encrypt.is_some(),
            self.export_pubkey.is_some(),
            self.del_pubkey.is_some(),
            self.del_keyset.is_some(),
            self.decrypt.is_some(),
            self.sign.is_some(),
            self.verify.is_some(),
        ]
        .iter()
        .filter(|&b| *b)
        .count()
    }

    #[inline(always)]
    pub fn fail_if_invalid(&self) -> Result<(), Box<dyn Error>> {
        if self.get_num_called() > 1 {
            return Err(Box::new(KdtErr::TooManyArgs));
        }
        Ok(())
    }
}
