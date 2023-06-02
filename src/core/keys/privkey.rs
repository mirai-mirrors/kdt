// -- imports --
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
    /// Base64-encoded bytes for private cryptographic
    /// (ie Kyber) key.
    pub crypto_key: String,

    /// Base64-encoded bytes for private signage
    /// (ie Dilithium) key.
    pub signage_key: String,

    /// Base64-encoded representation of the key
    /// owner's name.
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
    /// Creates a new `PrivKeyPair` object from the provided cryptographic key
    /// base64 string, the provided signage key string, and the owner base64
    /// string. This doesn't validate the passed inputs, so it *will* panic if
    /// you pass bad inputs.
    pub fn new(crypto_key: String, signage_key: String, owner: String) -> Self {
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
            .replace("\n", "")
            // Splits the private key into a cryptographic key and signage key.
            .split('*')
            .map(String::from)
            .collect();

        Self {
            crypto_key: privkey[0].to_owned(),
            signage_key: privkey[1].to_owned(),
            owner: privkey[2].to_owned(),
            id: String::new(),
        }
    }
}

// -- human-readable key output impl --
impl fmt::Display for PrivKeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // An asterisk separates the encryption key from the
        // signing key during key exchanges.
        let keypair = format!("{}*{}*{}", &self.crypto_key, &self.signage_key, &self.owner)
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
