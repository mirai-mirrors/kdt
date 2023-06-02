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
    SecretKey,
};
use std::{
    error::Error,
    fmt,
};

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
    pub fn encrypt_text(text: String, pubkey_str: String) -> Result<Message, Box<dyn Error>> {
        let pubkey = PubKeyPair::from_str(pubkey_str).init();
        let mut rng = rand::thread_rng();
        let (encrypted_secret, secret_bytes) =
            encapsulate(&Base64::decode_string(pubkey.crypto_key), &mut rng)?;
        let key = Key::<Aes256Gcm>::from_slice(&secret_bytes);
        let cipher = Aes256Gcm::new(&key);
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let encrypted_message =
            Base64::encode_bytes(&cipher.encrypt(&nonce, text.as_ref()).unwrap());
        let encoded_nonce = Base64::encode_bytes(&nonce.into_iter().collect::<Vec<u8>>());

        Ok(Message::new(
            Base64::encode_bytes(&encrypted_secret),
            encrypted_message,
            encoded_nonce,
        ))
    }

    /// Decrypts a pre-deserialized `Message` object with the
    /// provided private key. Note that, as stated above, this uses
    /// AES under the hood because of the magic way Kyber works -
    /// a shared symmetric key is established using the asymmetric
    /// keys, and then both parties can encrypt sensitive data
    /// with that! Pure magic, obviously.
    pub fn decrypt_msg(message: Message, privkey_str: String) -> String {
        // Uses the private key we have to decrypt the symmetric
        // shared secret.
        let secret_bytes = decapsulate(
            &Base64::decode_string(message.encrypted_secret),
            &Base64::decode_string(privkey_str),
        )
        .expect("You used the wrong private key!");
        let key = Key::<Aes256Gcm>::from_slice(&secret_bytes);
        let cipher = Aes256Gcm::new(&key);
        let nonce = Base64::decode_string(message.nonce);

        // Converts the raw text bytes to a UTF-8 encoded string.
        String::from_utf8_lossy(
            &cipher
                .decrypt(
                    &GenericArray::clone_from_slice(&nonce),
                    Base64::decode_string(message.encrypted_message).as_ref(),
                )
                .unwrap(),
        )
        .into()
    }
}

pub struct Message {
    /// The shared secret established by Kyber, encrypted
    /// asymmetrically so only you can see it.
    pub encrypted_secret: String,

    /// The actual encrypted data. This is a base64 encoded
    /// representation of the shifted bytes.
    pub encrypted_message: String,

    /// The AES-GCM nonce. From
    /// https://cryptography.io/en/latest/hazmat/primitives/symmetric-encryption/#cryptography.hazmat.primitives.ciphers.algorithms.ChaCha20:
    /// `The nonce does not need to be kept secret and may be included with the ciphertext.`
    pub nonce: String,
}

impl Message {
    /// Creates a new `Message` object from the given encrypted secret,
    /// encrypted message, and unencrypted nonce.
    pub fn new(encrypted_secret: String, encrypted_message: String, nonce: String) -> Self {
        Self {
            encrypted_secret,
            encrypted_message,
            nonce,
        }
    }

    /// Restores a `Message` object from the given message string.
    #[inline(always)]
    pub fn from_str(message: String) -> Self {
        let message_split: Vec<String> = message
            .chars()
            .skip(27)
            .take(message.len() - 27 - 26)
            .collect::<String>()
            .replace("\n", "")
            .split('*')
            .map(String::from)
            .collect();

        Self {
            encrypted_secret: message_split[0].to_owned(),
            encrypted_message: message_split[1].to_owned(),
            nonce: message_split[2].to_owned(),
        }
    }
}

impl fmt::Display for Message {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = format!(
            "{}*{}*{}",
            self.encrypted_secret, self.encrypted_message, self.nonce
        )
        .chars()
        .enumerate()
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
            "-----BEGIN KDT MESSAGE-----\n{}\n-----END KDT MESSAGE-----",
            message.trim_end()
        )
    }
}
