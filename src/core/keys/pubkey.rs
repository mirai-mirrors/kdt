// -- imports --
use crate::core::*;
use serde::{
    Deserialize,
    Serialize,
};
use sha2::{
    Digest,
    Sha256,
};
use std::fmt;

// -- public key pair (signing key + crypto key) --
#[derive(Serialize, Deserialize, Clone)]
pub struct PubKeyPair {
    /// Kyber public key bytes
    pub crypto_key: Vec<u8>,

    /// Dilithium public key bytes
    pub signage_key: Vec<u8>,

    /// Key owner's name as a string.
    pub owner: String,

    /// Sha256 hashsum of this object when the two
    /// above values are set. On initialization, this is
    /// `String::new()`, but a `PrivKeyPair::init()` call
    /// generates it on-demand. Ids are very important for key
    /// identification, so you should *always* call `PrivKeyPair::init()`
    /// after `PrivKeyPair::new()`.
    pub id: String,
}

impl PubKeyPair {
    /// Creates a new `PubKeyPair` object from the provided key
    /// bytearrays and owner string.
    #[inline(always)]
    pub fn new(crypto_key: Vec<u8>, signage_key: Vec<u8>, owner: String) -> Self {
        Self {
            crypto_key,
            signage_key,
            owner,
            id: String::new(),
        }
    }

    /// Computes a hash for the key pair, then sets the id as the hash. This
    /// helps maintain distinctness between key ids.
    #[inline(always)]
    pub fn init(mut self) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(self.to_string());
        self.id = format!("{:X}", hasher.finalize());
        self
    }

    /// Derives a `PubKeyPair` object from the provided KDT public
    /// key string. Doesn't validate input, so it *will* panic if you pass
    /// invalid inputs.
    pub fn from_str(pubkey_str: String) -> Self {
        let pubkey: Vec<Vec<u8>> = pubkey_str
            .chars()
            // Removes the `-----BEGIN KDT PUBKEY BLOCK-----` header.
            .skip(32)
            // Removes the `-----END KDT PRIVKEY BLOCK-----` footer.
            .take(pubkey_str.len() - 32 - 31)
            .collect::<String>()
            // Turns the human-readable formatting to something that can be parsed
            // programmatically.
            .replace('\n', "")
            // Splits the public key into a cryptographic key and signage key.
            .split('*')
            .map(String::from)
            .map(Base64::decode_string)
            .collect();

        Self {
            crypto_key: pubkey[0].to_owned(),
            signage_key: pubkey[1].to_owned(),
            owner: String::from_utf8_lossy(&pubkey[2]).to_string(),
            id: String::new(),
        }
    }
}

// -- human-readable key output impl --
impl fmt::Display for PubKeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let crypto_key = Base64::encode_bytes(&self.crypto_key);
        let signage_key = Base64::encode_bytes(&self.signage_key);
        let owner = Base64::encode_bytes(self.owner.as_bytes());
        // An asterisk separates the encryption key from the
        // signing key during key exchanges.
        let keypair = format!("{}*{}*{}", crypto_key, signage_key, owner)
            .chars()
            .enumerate()
            // This helps maintain readability when printing messages. It
            // inserts a new line at every nth (n = multiple of 64) character.
            // This is identical to GPG's output style.
            .flat_map(|(i, c)| {
                if (i + 1) % 64 == 0 {
                    vec![c, '\n']
                } else {
                    vec![c]
                }
            })
            .collect::<String>();
        write!(
            f,
            "-----BEGIN KDT PUBKEY BLOCK-----\n{}\n-----END KDT PUBKEY BLOCK-----",
            keypair.trim_end()
        )
    }
}
