#![forbid(unsafe_code)]

#[macro_use] pub mod core;
#[macro_use] mod verify_input;
mod chacha20_ietf;
mod xchacha20;
mod poly1305;
mod chachapoly_ietf;
mod xchachapoly;

pub use crate::{
	chacha20_ietf::ChaCha20Ietf, xchacha20::XChaCha20,
	poly1305::Poly1305,
	chachapoly_ietf::ChachaPolyIetf, xchachapoly::XChachaPoly
};
pub use crypto_api;
use std::{
	error::Error,
	fmt::{ self, Display, Formatter }
};


/// A ChaChaPoly-related error
#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub enum ChachaPolyError {
	/// The processed data is invalid (MAC-mismatch)
	InvalidData,
	/// An API misuse happened
	ApiMisuse(&'static str)
}
impl Display for ChachaPolyError {
	fn fmt(&self, f: &mut Formatter) -> fmt::Result {
		write!(f, "{:?}", self)
	}
}
impl Error for ChachaPolyError {}