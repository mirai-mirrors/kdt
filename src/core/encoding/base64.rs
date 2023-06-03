// -- imports --
use base64::{
    engine::general_purpose,
    Engine as _,
};
use std::fmt;

// -- simple base64 interface --
/// Incredibly minimalist base64 conversion object. Can
/// encode bytes, and decode strings. That's it, because that's
/// all we need.
pub struct Base64;

impl Base64 {
    /// Converts a bytearray to a base64 string.
    #[inline(always)]
    pub fn encode_bytes(b: &[u8]) -> String {
        general_purpose::STANDARD.encode(b)
    }

    /// Converts a base64 string to a bytearray.
    #[inline(always)]
    pub fn decode_string<S: fmt::Display>(s: S) -> Vec<u8> {
        general_purpose::STANDARD
            .decode(s.to_string())
            .unwrap()
    }
}
