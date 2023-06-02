// -- imports --
use crate::core::*;
use pqc_dilithium::Keypair as dilithium_keypair;
use pqc_kyber::keypair as kyber_keypair;

// -- fully controlled keyset (privkey pair + pubkey pair) --
#[derive(Serialize, Deserialize, Clone)]
pub struct OwnedKeySet {
    pub pubkey_pair: PubKeyPair,
    pub privkey_pair: PrivKeyPair,
}

impl OwnedKeySet {
    /// Generates a new key set (public, private; encryption, signage) on-demand.
    /// No errors should occur here, but if they do they probably aren't our fault
    /// (take a look at the libraries we use - they're probably the culprit!)
    pub fn generate(owner_name: String) -> Self {
        let encryption_keys = kyber_keypair(&mut rand::thread_rng());
        let signage_keys = dilithium_keypair::generate();
        let pubkey_pair = PubKeyPair::new(
            Base64::encode_bytes(&encryption_keys.public),
            Base64::encode_bytes(&signage_keys.public),
            Base64::encode_bytes(owner_name.as_bytes()),
        )
        .init();
        let privkey_pair = PrivKeyPair::new(
            Base64::encode_bytes(&encryption_keys.secret),
            Base64::encode_bytes(&signage_keys.expose_secret()),
            Base64::encode_bytes(owner_name.as_bytes()),
        )
        .init();

        Self {
            pubkey_pair,
            privkey_pair,
        }
    }

    /// Derives an `OwnedKeySet` from a public- and private-key base64 string pair.
    pub fn from_strs(pubkey_pair_str: String, privkey_pair_str: String) -> Self {
        Self {
            pubkey_pair: PubKeyPair::from_str(pubkey_pair_str).init(),
            privkey_pair: PrivKeyPair::from_str(privkey_pair_str).init(),
        }
    }
}
