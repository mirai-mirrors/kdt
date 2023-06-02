// -- compiler flags --
#![allow(unused_imports)]

// -- local modules (+ exports) --
pub mod crypto;
pub mod encoding;
pub mod errors;
pub mod keys;
pub mod logging;
pub mod signing;

pub use crypto::*;
pub use encoding::*;
pub use errors::*;
pub use keys::*;
pub use logging::*;
pub use signing::*;

// -- external imports --
use ron::{
    de::from_reader,
    ser::{
        to_string_pretty,
        PrettyConfig,
    },
};
use serde::{
    Deserialize,
    Serialize,
};
use std::{
    error::Error,
    fmt,
    fs::{
        self,
        File,
    },
    io::{
        Read,
        Write,
    },
    path::Path,
};

// -- core kdt object --
/// Highest level KDT object. Handles encryption, decryption,
/// signing, input validation, key importation, database loading,
/// etc.
pub struct CoreKdtHandler {
    /// Public key database, loaded in ram from `pubkeys.ron`.
    pub pubkey_db: PubKeyDb,

    /// Owned key database, loaded in ram from `ownedkeys.ron`.
    pub ownedkey_db: OwnedKeyDb,
}

impl CoreKdtHandler {
    /// Creates a new `CoreKdtHandler` by loading the necessary
    /// databases, and creating them if they don't exist.
    pub fn new() -> Result<Self, Box<dyn Error>> {
        if !Path::new("pubkeys.ron").exists() {
            let mut f = File::create("pubkeys.ron").unwrap();
            f.write_all(
                r#"(
    keys: []
)"#
                .as_bytes(),
            )
            .unwrap();
        }
        if !Path::new("ownedkeys.ron").exists() {
            let mut f = File::create("ownedkeys.ron").unwrap();
            f.write_all(
                r#"(
    keys: []
)"#
                .as_bytes(),
            )
            .unwrap();
        }
        let pubkey_db: PubKeyDb = match File::open("pubkeys.ron") {
            Ok(f) => match from_reader(f) {
                Ok(database) => database,
                Err(_) => return Err(Box::new(KdtErr::PubDbOpenFailed)),
            },
            Err(_) => return Err(Box::new(KdtErr::PubDbOpenFailed)),
        };
        let ownedkey_db: OwnedKeyDb = match File::open("ownedkeys.ron") {
            Ok(f) => match from_reader(f) {
                Ok(database) => database,
                Err(_) => return Err(Box::new(KdtErr::PrivDbOpenFailed)),
            },
            Err(_) => return Err(Box::new(KdtErr::PrivDbOpenFailed)),
        };
        Ok(Self {
            pubkey_db,
            ownedkey_db,
        })
    }

    /// Generates a new owned key set on demand, then
    /// appends that new keyset to the owned key database.
    pub fn gen_key(&mut self, name: String) -> String {
        let key = OwnedKeySet::generate(name);
        self.ownedkey_db.keys.push(key.clone());
        key.privkey_pair.id
    }

    /// Removes the public key with the specified id from the
    /// public key database in memory.
    pub fn del_pubkey(&mut self, keyid: String) {
        self.pubkey_db.keys = self
            .pubkey_db
            .keys
            .iter()
            .filter(|x| x.id != keyid)
            .map(|k| k.to_owned())
            .collect();
    }

    /// Removes the owned key set with the specified id from the
    /// owned key database in memory.
    pub fn del_ownedkey(&mut self, keyid: String) {
        self.ownedkey_db.keys = self
            .ownedkey_db
            .keys
            .iter()
            .filter(|k| k.privkey_pair.id != keyid)
            .map(|k| k.to_owned())
            .collect();
    }

    /// Adds the given public key to the in-memory key
    /// database.
    pub fn register_pubkey<S: fmt::Display>(
        &mut self, pubkey_str: S,
    ) -> Result<String, Box<dyn Error>> {
        // Construct a public key using the given string
        let pubkey = PubKeyPair::from_str(pubkey_str.to_string()).init();
        // Make sure this public key isn't already registered to the database
        if self
            .pubkey_db
            .keys
            .iter()
            .filter(|k| k.id == pubkey.id)
            .collect::<Vec<_>>()
            .len()
            != 0
        {
            Err(Box::new(KdtErr::KeyAlreadyExists))
        } else {
            // Add it to the database, then return the id
            self.pubkey_db.keys.push(pubkey.clone());
            Ok(pubkey.id)
        }
    }

    /// Dumps the public- and owned-key-databases to their
    /// respective files.
    pub fn dump_db(self) -> Result<(), Box<dyn Error>> {
        let pretty = PrettyConfig::new()
            .depth_limit(6)
            .separate_tuple_members(true);

        match File::create("pubkeys.ron") {
            Ok(ref mut f) => f
                .write_all(to_string_pretty(&self.pubkey_db, pretty.clone())?.as_bytes())
                .unwrap(),
            Err(_) => return Err(Box::new(KdtErr::DbDumpFailed)),
        }
        match File::create("ownedkeys.ron") {
            Ok(ref mut f) => f
                .write_all(format!("// This file contains the private-key-public-key pairs for your owned keys. These are used for decryption and signing. Don't share this file's contents with anyone!\n{}", to_string_pretty(&self.ownedkey_db, pretty)?).as_bytes())
                .unwrap(),
            Err(_) => return Err(Box::new(KdtErr::DbDumpFailed)),
        }

        Ok(())
    }

    /// Encrypts the given message against the public key of the given
    /// id.
    pub fn encrypt(&self, pubkey_id: String, text: String) -> String {
        let public_key = self.pubkey_db.get_by_id(pubkey_id).to_string();
        KdtCryptoHandler::encrypt_text(text, public_key)
            .unwrap()
            .to_string()
    }

    /// Decrypts the given message with the private key of the given id.
    pub fn decrypt(&self, privkey_id: String, message: String) -> String {
        let message = Message::from_str(message);
        let private_key = self
            .ownedkey_db
            .get_by_id(privkey_id)
            .privkey_pair
            .crypto_key;
        KdtCryptoHandler::decrypt_msg(message, private_key).to_string()
    }

    /// Signs the given message with the private key of the given id.
    pub fn sign(&self, privkey_id: String, text: String) -> String {
        let signing_pubkey = self
            .ownedkey_db
            .get_by_id(privkey_id.clone())
            .pubkey_pair
            .signage_key;
        let signing_privkey = self
            .ownedkey_db
            .get_by_id(privkey_id.clone())
            .privkey_pair
            .signage_key;
        KdtSignageHandler::sign_text(text, signing_privkey, signing_pubkey).to_string()
    }

    /// Verifies the given KDT-signed message with the public key of the
    /// given id.
    pub fn verify(&self, pubkey_id: String, full_text: String) -> Option<bool> {
        let verification_pubkey = self.pubkey_db.get_by_id(pubkey_id).signage_key;
        let parts: Vec<String> = full_text
            .chars()
            .skip(35)
            .take(full_text.len() - 35 - 27)
            .collect::<String>()
            .split("-----BEGIN KDT SIGNATURE-----")
            .map(|x| x.trim())
            .map(String::from)
            .collect();
        let text = parts.first()?.trim().to_owned();
        let signature = parts.last()?.replace("\n", "");
        Some(KdtSignageHandler::verify(
            text,
            signature,
            verification_pubkey,
        ))
    }
}
