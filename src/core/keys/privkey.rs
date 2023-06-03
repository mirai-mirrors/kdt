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

// -- private key pair (signing key + crypto key) --
#[derive(Serialize, Deserialize, Clone)]
pub struct PrivKeyPair {
    /// Kyber private key bytes
    pub crypto_key: Vec<u8>,

    /// Dilithium private key bytes
    pub signage_key: Vec<u8>,

    /// Key owner's name as a string
    pub owner: String,

    /// Sha256 hashsum of this object when the two
    /// above values are set. On initialization, this is
    /// `String::new()`, but a `PrivKeyPair::init()` call
    /// generates it on-demand. Ids are very important for key
    /// identification, so you should *always* call `PrivKeyPair::init()`
    /// after `PrivKeyPair::new()`.
    pub id: String,
}

impl PrivKeyPair {
    /// Creates a new `PrivKeyPair` object from the provided key
    /// bytearrays and owner string
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

    /// Derives a `PrivKeyPair` object from the provided KDT private
    /// key string. Doesn't validate input, so it *will* panic if you pass
    /// invalid inputs.
    pub fn from_str(privkey_str: String) -> Self {
        let privkey: Vec<String> = privkey_str
            .chars()
            // Removes the `-----BEGIN KDT PRIVKEY BLOCK-----` header.
            .skip(33)
            // Removes the `-----END KDT PRIVKEY BLOCK-----` footer.
            .take(privkey_str.len() - 33 - 32)
            .collect::<String>()
            // Turns the human-readable formatting to something that can be parsed
            // programmatically.
            .replace('\n', "")
            // Splits the private key into a cryptographic key and signage key.
            .split('*')
            .map(String::from)
            .collect();

        Self {
            crypto_key: Base64::decode_string(privkey[0].to_owned()),
            signage_key: Base64::decode_string(privkey[1].to_owned()),
            owner: String::from_utf8_lossy(&Base64::decode_string(&privkey[2])).to_string(),
            id: String::new(),
        }
    }
}

// -- human-readable key output impl --
impl fmt::Display for PrivKeyPair {
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
            "-----BEGIN KDT PRIVKEY BLOCK-----\n{}\n-----END KDT PRIVKEY BLOCK-----",
            keypair.trim_end()
        )
    }
}
