// -- imports --
use crate::core::*;
use std::fmt;

pub struct KdtSignedMessage {
    /// Message string
    pub message: String,

    /// Dilithium signature bytes
    pub signature: Vec<u8>,
}

impl KdtSignedMessage {
    #[inline(always)]
    pub fn new<S: fmt::Display>(message: S, signature: Vec<u8>) -> Self {
        Self {
            message: message.to_string(),
            signature,
        }
    }
}

impl KdtMessage for KdtSignedMessage {
    fn from_str<S: fmt::Display>(full_signature: S) -> Self {
        let parts: Vec<String> = full_signature
            .to_string()
            .chars()
            .skip(35)
            .take(full_signature.to_string().len() - 35 - 27)
            .collect::<String>()
            .split("-----BEGIN KDT SIGNATURE-----")
            .map(|x| x.trim())
            .map(String::from)
            .collect();
        let text = parts.first().unwrap().trim().to_owned();
        let signature_str = parts.last().unwrap().replace('\n', "");

        Self {
            message: text,
            signature: Base64::decode_string(signature_str),
        }
    }
}

impl fmt::Display for KdtSignedMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let fmt_sig = Base64::encode_bytes(&self.signature);
        let sig = format!("-----BEGIN KDT SIGNED MESSAGE-----\n{}\n\n-----BEGIN KDT SIGNATURE-----\n{}\n-----END KDT SIGNATURE-----", self.message, fmt_sig.chars()
        .enumerate()
        .flat_map(|(i, c)| {
            if (i + 1) % 64 == 0 {
                vec![c, '\n']
            } else {
                vec![c]
            }
        })
        .collect::<String>());
        write!(f, "{}", sig)
    }
}
