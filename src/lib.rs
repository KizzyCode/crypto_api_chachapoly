#[macro_use] mod macros;
mod chacha20_ietf;
mod poly1305;
mod chachapoly_ietf;


pub use crate::{ chacha20_ietf::ChaCha20Ietf, poly1305::Poly1305, chachapoly_ietf::ChachaPolyIetf };
use std::{
	error::Error,
	fmt::{ Display, Formatter, Result as FmtResult }
};


#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub enum ChachaPolyError {
	InvalidData,
	ApiMisuse(&'static str)
}
impl Display for ChachaPolyError {
	fn fmt(&self, f: &mut Formatter) -> FmtResult {
		write!(f, "{:?}", self)
	}
}
impl Error for ChachaPolyError {}