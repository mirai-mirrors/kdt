// -- imports --
use std::fmt;

pub trait KdtMessage {
    fn from_str<S: fmt::Display>(message_str: S) -> Self;
}
