// -- imports --
use crate::core::*;
use aes_gcm::{
    aead::{
        Aead,
        AeadCore,
        KeyInit,
        OsRng,
    },
    Aes256Gcm,
    Key,
};
use generic_array::GenericArray;
use pqc_kyber::{
    decapsulate,
    encapsulate,
};
use std::error::Error;

// -- base crypto handling --
/// Core cryptography handler for KDT. Handles everything when
/// it comes to AES and Kyber. Signatures are handled by the
/// `KdtSignageHandler` though.
pub struct KdtCryptoHandler;

impl KdtCryptoHandler {
    /// Encrypts a string of text against the provided Kyber
    /// public key. We use AES in the backend here because
    /// the way Kyber works is that it establishes a shared
    /// symmetric key inside of the asymmetric stuff. Magic!
    pub fn encrypt_text(
        text: String, pubkey: Vec<u8>,
    ) -> Result<KdtEncryptedMessage, Box<dyn Error>> {
        let mut rng = rand::thread_rng();
        let (encrypted_secret, secret_bytes) = encapsulate(&pubkey, &mut rng)?;
        let key = Key::<Aes256Gcm>::from_slice(&secret_bytes);
        let cipher = Aes256Gcm::new(key);
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let encrypted_message = cipher.encrypt(&nonce, text.as_ref()).unwrap();
        let nonce = nonce.into_iter().collect::<Vec<u8>>();

        Ok(KdtEncryptedMessage::new(
            encrypted_secret.to_vec(),
            encrypted_message,
            nonce,
        ))
    }

    /// Decrypts a pre-deserialized `Message` object with the
    /// provided private key. Note that, as stated above, this uses
    /// AES under the hood because of the magic way Kyber works -
    /// a shared symmetric key is established using the asymmetric
    /// keys, and then both parties can encrypt sensitive data
    /// with that! Pure magic, obviously.
    pub fn decrypt_msg(message: KdtEncryptedMessage, privkey: Vec<u8>) -> String {
        // Uses the private key we have to decrypt the symmetric
        // shared secret.
        let secret_bytes = decapsulate(&message.encrypted_secret, &privkey)
            .expect("You used the wrong private key!");
        let key = Key::<Aes256Gcm>::from_slice(&secret_bytes);
        let cipher = Aes256Gcm::new(key);
        let nonce = message.nonce;

        // Converts the raw text bytes to a UTF-8 encoded string.
        String::from_utf8_lossy(
            &cipher
                .decrypt(
                    &GenericArray::clone_from_slice(&nonce),
                    message.encrypted_message.as_ref(),
                )
                .unwrap(),
        )
        .into()
    }
}
