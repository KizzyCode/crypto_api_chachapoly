use json::{ JsonValue, iterators::Members };


/// An extension for `json::JsonValue`
pub trait JsonValueExt {
	/// Decodes a string value or panics
	fn checked_string(&self) -> String;
	/// Hex-decodes the string value into a byte vector or panics
	fn checked_bytes(&self) -> Vec<u8>;
	/// Ensures that `self` is not `null`
	fn checked_array_iter(&self) -> Members;
	
	/// Gets an usize if `self` is not `null` or returns `def`
	fn optional_usize(&self, def: usize) -> usize;
	/// Gets a string if `self` is not `null` or returns `def`
	fn optional_string(&self, def: impl ToString) -> String;
}
impl JsonValueExt for JsonValue {
	fn checked_string(&self) -> String {
		self.as_str().unwrap().to_string()
	}
	fn checked_bytes(&self) -> Vec<u8> {
		let encoded = self.as_str().unwrap();
		hex::decode(encoded).unwrap()
	}
	fn checked_array_iter(&self) -> Members {
		assert!(self.is_array());
		self.members()
	}
	fn optional_usize(&self, def: usize) -> usize {
		match self.is_number() {
			true => self.as_usize().unwrap(),
			false => def
		}
	}
	fn optional_string(&self, def: impl ToString) -> String {
		match self.is_string() {
			true => self.as_str().unwrap().to_string(),
			false => def.to_string()
		}
	}
}


/// An extension for result types
pub trait ResultExt<T, E> {
	/// Unwraps the error or executes the panic function `p`
	fn error_or(self, msg: impl ToString) -> E;
}
impl<T, E> ResultExt<T, E> for Result<T, E> {
	fn error_or(self, m: impl ToString) -> E {
		match self {
			Err(e) => e,
			_ => panic!(m.to_string())
		}
	}
}