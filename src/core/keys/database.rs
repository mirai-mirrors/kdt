// -- imports --
use crate::core::*;
use serde::{
    Deserialize,
    Serialize,
};

// -- public key database --
#[derive(Serialize, Deserialize)]
/// A database of public keys stored locally in
/// `pubkeys.ron`.
pub struct PubKeyDb {
    /// A list of public key objects.
    pub keys: Vec<PubKeyPair>,
}

impl PubKeyDb {
    /// Takes in the hexadecimal string id of a public key, and returns
    /// the public key object.
    pub fn get_by_id(&self, id: String) -> Result<PubKeyPair, Box<dyn Error>> {
        let filtered = self
            .keys
            .iter()
            .filter(|k| k.id == id)
            .collect::<Vec<_>>();
        if filtered.len() != 1 {
            Err(Box::new(KdtErr::BadKeyId))
        } else {
            Ok(filtered[0].clone())
        }
    }

    /// Shorthand for `self.keys.is_empty()` to avoid deep nesting
    /// and pointlessly annoying function access.
    #[inline(always)]
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
}

// -- owned key database --
#[derive(Serialize, Deserialize)]
/// A database of owned keys (ie private-public pairs) stored
/// locally in `ownedkeys.ron`. Remember, `ownedkeys.ron` is for your
/// eyes only - don't let anyone else see it!
pub struct OwnedKeyDb {
    /// A list of private- and public-key pairs that you're in control of.
    pub keys: Vec<OwnedKeySet>,
}

impl OwnedKeyDb {
    /// Takes in the hexadecimal string id of a private key,
    /// and returns the private-public key pair.
    pub fn get_by_id(&self, id: String) -> Result<OwnedKeySet, Box<dyn Error>> {
        let filtered = self
            .keys
            .iter()
            .filter(|k| k.privkey_pair.id == id)
            .collect::<Vec<_>>();
        if filtered.len() != 1 {
            Err(Box::new(KdtErr::BadKeyId))
        } else {
            Ok(filtered[0].clone())
        }
    }

    /// Shorthand for `self.keys.is_empty()` to avoid deep nesting
    /// and pointlessly annoying function access.
    #[inline(always)]
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
}
