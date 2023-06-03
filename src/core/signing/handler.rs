// -- imports --
use crate::core::*;
use pqc_dilithium::verify as dilithium_verify;
use pqc_dilithium::Keypair;

// -- signage handler struct --
/// Base Dilithium signature handler object. Incredibly WIP.
pub struct KdtSignageHandler;

impl KdtSignageHandler {
    /// Generates a KDT Dilithium signature from a passed message
    /// and a key pair, then formats the message with the signature
    /// in a visually appealing way (mostly just stole GPG's output
    /// styling).
    #[inline(always)]
    pub fn sign_text(text: String, signkey: Keypair) -> String {
        format!("-----BEGIN KDT SIGNED MESSAGE-----\n{}\n\n-----BEGIN KDT SIGNATURE-----\n{}\n-----END KDT SIGNATURE-----", text, Base64::encode_bytes(&signkey.sign(text.as_bytes())).chars()
        .enumerate()
        .flat_map(|(i, c)| {
            if (i + 1) % 64 == 0 {
                vec![c, '\n']
            } else {
                vec![c]
            }
        })
        .collect::<String>())
    }

    /// Verifies a KDT dilithium-signed message against its
    /// corresponding public key.
    #[inline(always)]
    pub fn verify(signed_message: KdtSignedMessage, pubkey: Vec<u8>) -> bool {
        let text_bytes = signed_message.message.as_bytes();
        let sig_bytes = signed_message.signature;
        dilithium_verify(&sig_bytes, text_bytes, &pubkey).is_ok()
    }
}
