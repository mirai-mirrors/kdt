// -- imports --
use crate::core::*;
use std::fmt;

pub struct KdtEncryptedMessage {
    /// The shared secret established by Kyber, encrypted
    /// asymmetrically so only you can see it.
    pub encrypted_secret: Vec<u8>,

    /// The actual encrypted data.
    pub encrypted_message: Vec<u8>,

    /// The AES-GCM nonce. From
    /// https://cryptography.io/en/latest/hazmat/primitives/symmetric-encryption/#cryptography.hazmat.primitives.ciphers.algorithms.ChaCha20:
    /// `The nonce does not need to be kept secret and may be included with the ciphertext.`
    pub nonce: Vec<u8>,
}

impl KdtEncryptedMessage {
    /// Creates a new `Message` object from the given encrypted secret,
    /// encrypted message, and unencrypted nonce.
    pub fn new(encrypted_secret: Vec<u8>, encrypted_message: Vec<u8>, nonce: Vec<u8>) -> Self {
        Self {
            encrypted_secret,
            encrypted_message,
            nonce,
        }
    }

    /// Restores a `Message` object from the given message string.
    pub fn from_str(message: String) -> Self {
        let message_split: Vec<String> = message
            .chars()
            .skip(27)
            .take(message.len() - 27 - 26)
            .collect::<String>()
            .replace('\n', "")
            .split('*')
            .map(String::from)
            .collect();

        Self {
            encrypted_secret: Base64::decode_string(&message_split[0]),
            encrypted_message: Base64::decode_string(&message_split[1]),
            nonce: Base64::decode_string(&message_split[2]),
        }
    }
}

impl fmt::Display for KdtEncryptedMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let encoded_secret = Base64::encode_bytes(&self.encrypted_secret);
        let encoded_message = Base64::encode_bytes(&self.encrypted_message);
        let encoded_nonce = Base64::encode_bytes(&self.nonce);

        let message = format!("{}*{}*{}", encoded_secret, encoded_message, encoded_nonce,)
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
            message.trim()
        )
    }
}
