// -- imports --
use core::fmt;
use std::error::Error;

// -- error struct --
#[derive(Debug)]
/// Custom error struct. Helps ensure error handling
/// doesn't get *too* ugly.
pub enum KdtErr {
    TooManyArgs,
    PubDbOpenFailed,
    PrivDbOpenFailed,
    DbDumpFailed,
    KeyAlreadyExists,
}

impl fmt::Display for KdtErr {
    #[inline(always)]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::TooManyArgs => write!(
                f,
                "Too many arguments were passed! You can only use one argument at a time."
            ),
            Self::PubDbOpenFailed => write!(f, "Failed to open public keys database!"),
            Self::PrivDbOpenFailed => write!(f, "Failed to open private keys database!"),
            Self::DbDumpFailed => write!(f, "Failed to dump to database!"),
            Self::KeyAlreadyExists => write!(f, "This key already exists in the database!"),
        }
    }
}

// Pointless trait implementation to ensure `KdtErr` is
// considered an `Error` type so you can return it
// in a function that returns eg `Result<(), Box<dyn Error>>`.
impl Error for KdtErr {}
